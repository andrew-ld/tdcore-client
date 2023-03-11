#include "td/actor/ConcurrentScheduler.h"
#include "td/actor/impl/Actor-decl.h"
#include "td/actor/impl/ActorId-decl.h"
#include "td/actor/impl/Scheduler-decl.h"
#include "td/db/DbKey.h"
#include "td/td/mtproto/AuthData.h"
#include "td/td/mtproto/AuthKey.h"
#include "td/td/telegram/net/Session.h"
#include "td/telegram/Global.h"
#include "td/telegram/net/AuthDataShared.h"
#include "td/telegram/net/ConnectionCreator.h"
#include "td/telegram/net/DcId.h"
#include "td/telegram/net/DcOptions.h"
#include "td/telegram/net/MtprotoHeader.h"
#include "td/telegram/net/NetQuery.h"
#include "td/telegram/net/NetQueryDispatcher.h"
#include "td/telegram/net/NetQueryStats.h"
#include "td/telegram/net/PublicRsaKeyShared.h"
#include "td/telegram/OptionManager.h"
#include "td/telegram/StateManager.h"
#include "td/telegram/Td.h"
#include "td/telegram/TdCallback.h"
#include "td/telegram/TdParameters.h"
#include "td/utils/logging.h"
#include "td/utils/unique_ptr.h"
#include <algorithm>
#include <memory>
#include <string>
#include <utility>

namespace tdcore {
class TdCoreSessionCallback final : public td::Session::Callback {
 public:
  TdCoreSessionCallback(td::ActorShared<> parent, td::DcOption option) : parent_(std::move(parent)), option_(option) {
  }
  void on_failed() final {
    // nop
  }
  void on_closed() final {
    // nop
  }
  void request_raw_connection(td::unique_ptr<td::mtproto::AuthData> auth_data,
                              td::Promise<td::unique_ptr<td::mtproto::RawConnection>> promise) final {
    send_closure(
        td::G()->connection_creator(), &td::ConnectionCreator::request_raw_connection_by_ip, option_.get_ip_address(),
        td::mtproto::TransportType{td::mtproto::TransportType::ObfuscatedTcp,
                                   td::narrow_cast<td::int16>(option_.get_dc_id().get_raw_id()), option_.get_secret()},
        std::move(promise));
  }
  void on_tmp_auth_key_updated(td::mtproto::AuthKey auth_key) final {
    // nop
  }
  void on_server_salt_updated(std::vector<td::mtproto::ServerSalt> server_salts) final {
    // nop
  }
  void on_update(td::BufferSlice &&update, td::uint64 auth_key_id) final {
    // nop
  }
  void on_result(td::NetQueryPtr net_query) final {
    td::G()->net_query_dispatcher().dispatch(std::move(net_query));
  }

 private:
  td::DcOption option_;
  td::ActorShared<> parent_;
};

class TdCallbackImpl : public td::TdCallback {
 public:
  explicit TdCallbackImpl() {
  }

  void on_error(std::uint64_t id, td::td_api::object_ptr<td::td_api::error> error) override {
  }

  void on_result(std::uint64_t id, td::td_api::object_ptr<td::td_api::Object> result) override {
  }
};

class CoreTdApplication final : public td::NetQueryCallback {
 private:
  td::TdParameters parameters_;
  td::ActorOwn<td::Session> session_;
  td::ActorOwn<td::Td> td_;
  td::ActorOwn<td::StateManager> state_manager_;
  td::ActorOwn<td::ConnectionCreator> connection_creator_;

 public:
  CoreTdApplication(td::TdParameters parameters) : parameters_(parameters) {
  }

  void start_up() final {
    auto old_context = set_context(std::make_shared<td::Global>());

    td_ = td::create_actor<td::Td>("Td", std::move(td::make_unique<TdCallbackImpl>()), td::Td::Td::Options{});
    state_manager_ = td::create_actor<td::StateManager>("StateManager", actor_shared(this));
    connection_creator_ = td::create_actor<td::ConnectionCreator>("ConnectionCreator", actor_shared(this));

    td::G()->set_state_manager(state_manager_.get());
    td::G()->set_connection_creator(std::move(connection_creator_));

    auto database_promise = td::PromiseCreator::lambda(
        [actor_id = actor_id(this), this](td::Result<td::TdDb::OpenedDatabase> r_opened_database) {
          if (r_opened_database.is_error()) {
            LOG(FATAL) << "unable to open database " << r_opened_database.error();
          }

          td::G()->init(parameters_, std::move(td_.get()), r_opened_database.move_as_ok().database).ensure();
        });

    td::TdDb::open(td::Scheduler::instance()->sched_id(), parameters_, std::move(td::DbKey::empty()),
                   std::move(database_promise));

    td::G()->set_net_query_stats(std::make_shared<td::NetQueryStats>());
    td::G()->set_option_manager(new td::OptionManager(std::move(td_.get().get_actor_unsafe())));
    td::G()->set_net_query_dispatcher(td::make_unique<td::NetQueryDispatcher>());

    td::MtprotoHeader::Options mtproto_header = {
        .api_id = parameters_.api_id,
        .system_language_code = "en",
        .device_model = "tdcore",
        .system_version = "1",
        .application_version = "1",
        .language_pack = "en",
        .language_code = "en",
    };

    td::G()->set_mtproto_header(td::make_unique<td::MtprotoHeader>(mtproto_header));
  }

  void create_session(td::DcId dc_id) {
    auto tdguard = td::create_shared_lambda_guard([]() {});

    auto public_rsa_key = std::make_shared<td::PublicRsaKeyShared>(td::DcId::empty(), false);

    auto auth_data = td::AuthDataShared::create(dc_id, std::move(public_rsa_key), std::move(tdguard));

    auto dc_options = td::ConnectionCreator::get_default_dc_options(false);

    auto dc_option = std::find_if(dc_options.dc_options.begin(), dc_options.dc_options.end(),
                                  [dc_id](td::DcOption o) { return o.get_dc_id().get_raw_id() == dc_id.get_raw_id(); });

    if (dc_option == dc_options.dc_options.end()) {
      LOG(FATAL) << "unable to find dc option for " << dc_id.get_raw_id();
    }

    auto callback = td::make_unique<TdCoreSessionCallback>(
        actor_shared(this, 1), std::move(td::DcOption(dc_option->get_dc_id(), dc_option->get_ip_address())));

    session_ = td::create_actor<td::Session>("MainSession", std::move(callback), std::move(auth_data),
                                             dc_id.get_raw_id(), dc_id.get_value(), true, true, false, false, false,
                                             td::mtproto::AuthKey(), std::vector<td::mtproto::ServerSalt>());

    auto query =
        td::G()->net_query_creator().create(td::UniqueId::next(), td::telegram_api::help_getConfig(), {},
                                            td::DcId::main(), td::NetQuery::Type::Common, td::NetQuery::AuthFlag::On);

    query->set_callback(actor_shared(this));

    td::send_closure(state_manager_, &td::StateManager::on_network, td::NetType::Other);
    td::send_closure(session_, &td::Session::send, std::move(query));
  }

  void on_result(td::NetQueryPtr query) final {
    LOG(DEBUG) << "received response" << query->tl_constructor();
  }

  void hangup_shared() final {
    stop();
  }

  void hangup() final {
    session_.reset();
    td_.reset();
    state_manager_.reset();
    connection_creator_.reset();
  }

  void timeout_expired() final {
    session_.reset();
    td_.reset();
    state_manager_.reset();
    connection_creator_.reset();
  }
};
}  // namespace tdcore

int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));

  td::ConcurrentScheduler sched(4, 0);

  td::TdParameters parameters = {
      .database_directory = "/tmp/tdcore_database",
      .files_directory = "/tmp/tdcore_files",
      .api_id = 422048,
      .api_hash = "12dca97b861c78ae7437239bbf0f74f5",
  };

  {
    auto guard = sched.get_main_guard();
    auto with_context = td::create_actor<tdcore::CoreTdApplication>("WithContext", parameters).release();
    td::send_closure(with_context, &tdcore::CoreTdApplication::create_session, td::DcId::create(4));
  }

  sched.start();

  while (sched.run_main(10))
    ;

  sched.finish();

  return 0;
}

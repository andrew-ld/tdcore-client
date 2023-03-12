#include "td/actor/ConcurrentScheduler.h"
#include "td/actor/impl/Actor-decl.h"
#include "td/actor/impl/ActorId-decl.h"
#include "td/actor/impl/Scheduler-decl.h"
#include "td/actor/SleepActor.h"
#include "td/db/DbKey.h"
#include "td/td/mtproto/AuthData.h"
#include "td/td/mtproto/AuthKey.h"
#include "td/td/telegram/net/Session.h"
#include "td/telegram/Global.h"
#include "td/telegram/net/AuthDataShared.h"
#include "td/telegram/net/ConnectionCreator.h"
#include "td/telegram/net/DcId.h"
#include "td/telegram/net/MtprotoHeader.h"
#include "td/telegram/net/NetQuery.h"
#include "td/telegram/net/NetQueryStats.h"
#include "td/telegram/net/NetStatsManager.h"
#include "td/telegram/net/PublicRsaKeyShared.h"
#include "td/telegram/OptionManager.h"
#include "td/telegram/StateManager.h"
#include "td/telegram/Td.h"
#include "td/telegram/TdCallback.h"
#include "td/telegram/TdDb.h"
#include "td/telegram/TdParameters.h"
#include "td/telegram/telegram_api.h"
#include "td/utils/buffer.h"
#include "td/utils/int_types.h"
#include "td/utils/logging.h"
#include "td/utils/port/thread.h"
#include "td/utils/Promise.h"
#include "td/utils/ScopeGuard.h"
#include "td/utils/SliceBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/unique_ptr.h"
#include <algorithm>
#include <memory>
#include <string>
#include <utility>

namespace tdcore {
class TdCoreSessionCallback final : public td::Session::Callback {
 public:
  TdCoreSessionCallback(td::ActorShared<> parent, td::DcId dc_id, std::shared_ptr<td::AuthDataShared> auth_data)
      : parent_(std::move(parent)), dc_id_(dc_id), auth_data_(std::move(auth_data)) {
  }
  void on_failed() final {
    // nop
  }
  void on_closed() final {
    parent_.reset();
    auth_data_.reset();
  }
  void request_raw_connection(td::unique_ptr<td::mtproto::AuthData> auth_data,
                              td::Promise<td::unique_ptr<td::mtproto::RawConnection>> promise) final {
    send_closure(td::G()->connection_creator(), &td::ConnectionCreator::request_raw_connection, dc_id_, false, false,
                 std::move(promise), 1L, std::move(auth_data));
  }
  void on_tmp_auth_key_updated(td::mtproto::AuthKey auth_key) final {
    // nop
  }
  void on_server_salt_updated(std::vector<td::mtproto::ServerSalt> server_salts) final {
    auth_data_->set_future_salts(std::move(server_salts));
  }
  void on_update(td::BufferSlice &&update, td::uint64 auth_key_id) final {
    // nop
  }
  void on_result(td::NetQueryPtr net_query) final {
    auto callback = net_query->move_callback();

    if (callback.empty()) {
      LOG(ERROR) << "unable to find callback for query " << net_query->id();
    } else {
      td::send_closure_later(std::move(callback), &td::NetQueryCallback::on_result, std::move(net_query));
    }
  }

 private:
  td::DcId dc_id_;
  td::ActorShared<> parent_;
  std::shared_ptr<td::AuthDataShared> auth_data_;
};

class TdCallbackStub final : public td::TdCallback {
 public:
  explicit TdCallbackStub() {
  }

  void on_error(std::uint64_t id, td::td_api::object_ptr<td::td_api::error> error) override {
  }

  void on_result(std::uint64_t id, td::td_api::object_ptr<td::td_api::Object> result) override {
  }
};

class TdCoreNetQueryCallback final : public td::NetQueryCallback {
 public:
  explicit TdCoreNetQueryCallback(td::ActorShared<> parent, td::Promise<td::NetQueryPtr> promise)
      : parent_(std::move(parent)), promise_(std::move(promise)) {
  }

  void on_result(td::NetQueryPtr query) final {
    promise_.set_result(std::move(query));
    parent_.reset();
  }

 private:
  td::Promise<td::NetQueryPtr> promise_;
  td::ActorShared<> parent_;
};

class TdCoreApplication final : public td::Actor {
 private:
  td::TdParameters parameters_;
  td::DcId dc_id_;
  std::uint64_t identifier_;

  td::int32 shared_ref_cnt_ = 0;

  td::ActorOwn<td::Td> td_;
  td::unique_ptr<td::TdDb> td_db_;
  td::ActorOwn<td::Session> session_;
  td::ActorOwn<td::StateManager> state_manager_;
  td::ActorOwn<td::ConnectionCreator> connection_creator_;
  td::ActorOwn<td::NetStatsManager> net_stats_manager_;
  td::unique_ptr<td::OptionManager> option_manager_;

  std::shared_ptr<td::ActorContext> old_context_;

  td::ActorShared<> create_reference(td::uint64 id) {
    shared_ref_cnt_++;
    return actor_shared(this, id);
  }

  static const td::int32 get_database_scheduler_id() {
    auto current_scheduler_id = td::Scheduler::instance()->sched_id();
    auto scheduler_count = td::Scheduler::instance()->sched_count();
    return td::min(current_scheduler_id + 1, scheduler_count - 1);
  }

 public:
  TdCoreApplication(td::TdParameters parameters, td::DcId dc_id, td::unique_ptr<td::TdDb> td_db)
      : parameters_(parameters), dc_id_(dc_id), td_db_(std::move(td_db)) {
    identifier_ = std::hash<std::string>{}(parameters.database_directory);
  }

  static void open(td::Promise<td::ActorOwn<TdCoreApplication>> promise, td::TdParameters parameters, td::DcId dc_id,
                   td::int32 application_scheduler = 0) {
    auto database_promise = td::PromiseCreator::lambda(
        [=, promise = std::move(promise)](td::Result<td::TdDb::OpenedDatabase> r_opened_database) mutable {
          if (r_opened_database.is_error()) {
            promise.set_error(std::move(r_opened_database.move_as_error()));
            return;
          }

          auto application = td::create_actor_on_scheduler<TdCoreApplication>(
              "Application", application_scheduler, parameters, dc_id, r_opened_database.move_as_ok().database);

          promise.set_result(std::move(application));
        });

    td::TdDb::open(get_database_scheduler_id(), parameters, td::DbKey::empty(), std::move(database_promise));
  }

  void start_up() final {
    old_context_ = set_context(std::make_shared<td::Global>());

    td_ = td::create_actor<td::Td>("Td", std::move(td::make_unique<TdCallbackStub>()), td::Td::Td::Options{});

    state_manager_ =
        td::create_actor<td::StateManager>(PSTRING() << "StateManager:" << identifier_, create_reference(1));
    connection_creator_ =
        td::create_actor<td::ConnectionCreator>(PSTRING() << "ConnectionCreator:" << identifier_, create_reference(2));
    net_stats_manager_ =
        td::create_actor<td::NetStatsManager>(PSTRING() << "NetStatsManager:" << identifier_, create_reference(3));

    td::G()->set_state_manager(state_manager_.get());

    // setup network stats
    {
      auto net_stats_manager_ptr = net_stats_manager_.get_actor_unsafe();
      net_stats_manager_ptr->init();

      connection_creator_.get_actor_unsafe()->set_net_stats_callback(net_stats_manager_ptr->get_common_stats_callback(),
                                                                     net_stats_manager_ptr->get_media_stats_callback());

      td::G()->set_net_stats_file_callbacks(net_stats_manager_ptr->get_file_stats_callbacks());
      td::G()->set_net_query_stats(std::make_shared<td::NetQueryStats>());
      td::G()->set_connection_creator(std::move(connection_creator_));
    }

    // setup database
    {
      td::G()->init(parameters_, std::move(td_.get()), std::move(td_db_)).ensure();
      option_manager_ = td::make_unique<td::OptionManager>(td_.get().get_actor_unsafe());
      td::G()->set_option_manager(option_manager_.get());
    }

    // setup mtproto headers
    {
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

    // setup session
    {
      auto public_rsa_key = std::make_shared<td::PublicRsaKeyShared>(td::DcId::empty(), false);

      auto td_guard = td::create_shared_lambda_guard([actor = create_reference(4)]() {});

      auto auth_data = td::AuthDataShared::create(dc_id_, std::move(public_rsa_key), td_guard);

      auto callback = td::make_unique<TdCoreSessionCallback>(create_reference(5), dc_id_, auth_data);

      session_ =
          td::create_actor<td::Session>(PSTRING() << "MainSession:" << identifier_, std::move(callback),
                                        std::move(auth_data), dc_id_.get_raw_id(), dc_id_.get_value(), true, true,
                                        false, false, false, auth_data->get_auth_key(), auth_data->get_future_salts());
    }

    td::send_closure(state_manager_, &td::StateManager::on_network, td::NetType::Other);
  }

  void perform_network_query(const td::telegram_api::Function &function, td::Promise<td::NetQueryPtr> promise) {
    const auto has_closed = td::Scheduler::context()->get_id() != td::Global::ID || td::G()->close_flag();

    if (has_closed) {
      promise.set_error(td::Status::Error(202, "Client distroyed"));
      return;
    }

    auto query = td::G()->net_query_creator().create(td::UniqueId::next(), function, {}, dc_id_,
                                                     td::NetQuery::Type::Common, td::NetQuery::AuthFlag::On);

    query->set_callback(td::create_actor<TdCoreNetQueryCallback>(
        PSTRING() << "NetworkQueryCallback:" << identifier_ << ":" << query->id(), create_reference(6),
        std::move(promise)));

    td::send_closure(session_, &td::Session::send, std::move(query));
  }

  void destroy() {
    td::G()->set_close_flag();
    td::send_closure(session_, &td::Session::close);
  }

  void hangup_shared() {
    shared_ref_cnt_--;

    LOG(DEBUG) << "hangup received, references: " << shared_ref_cnt_ << " dereferenced id: " << get_link_token()
               << " identifier: " << identifier_;

    if (shared_ref_cnt_ == 0 && get_link_token() == 7) {
      set_context(std::move(old_context_));
      stop();
      return;
    }

    if (shared_ref_cnt_ == 0) {
      td::Promise<> close_db_promise =
          td::PromiseCreator::lambda([actor_id = create_reference(7)](td::Unit) mutable { actor_id.reset(); });

      td::G()->close_and_destroy_all(std::move(close_db_promise));
    }

    if (shared_ref_cnt_ != 4) {
      return;
    }

    session_.reset();
    state_manager_.reset();
    connection_creator_.reset();
    net_stats_manager_.reset();
    td_.reset();
    option_manager_.reset();
    td_db_.reset();

    td::G()->set_connection_creator(td::ActorOwn<td::ConnectionCreator>());
    td::G()->set_option_manager(nullptr);
  }
};
}  // namespace tdcore

int main(int argc, char *argv[]) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));

  td::ConcurrentScheduler sched(td::thread::hardware_concurrency(), 0);

  td::DcId dc_id = td::DcId::create(4);

  const auto max_application_scheduler = td::max(td::thread::hardware_concurrency() - 1, 1u);

  {
    auto guard = sched.get_main_guard();

    for (auto count = 0; count < 50; count++) {
      td::TdParameters parameters = {
          .database_directory = PSTRING() << "/tmp/tdcore_database" << count,
          .files_directory = PSTRING() << "/tmp/tdcore_files" << count,
          .api_id = 422048,
          .api_hash = "12dca97b861c78ae7437239bbf0f74f5",
      };

      auto app_promise = td::PromiseCreator::lambda([](td::Result<td::ActorOwn<tdcore::TdCoreApplication>> r_app) {
        if (r_app.is_error()) {
          LOG(FATAL) << "unable to open TdCoreApplication: " << r_app.move_as_error().message();
        }

        auto app = r_app.move_as_ok().release();

        {
          auto query = td::telegram_api::help_getConfig();

          auto query_promise = td::PromiseCreator::lambda([](td::NetQueryPtr res) { LOG(DEBUG) << "result: " << res; });

          td::send_closure(app, &tdcore::TdCoreApplication::perform_network_query, std::move(query),
                           std::move(query_promise));
        }

        auto post_close_promise =
            td::PromiseCreator::lambda([app](td::Unit) { td::send_closure(app, &tdcore::TdCoreApplication::destroy); });

        td::create_actor<td::SleepActor>("PostClose", 5, std::move(post_close_promise)).release();
      });

      tdcore::TdCoreApplication::open(std::move(app_promise), parameters, dc_id, count % max_application_scheduler);
    }

    auto destroy_promise = td::PromiseCreator::lambda([](td::Unit) { td::Scheduler::instance()->finish(); });

    td::create_actor<td::SleepActor>("Destroy", 10, std::move(destroy_promise)).release();
  }

  sched.start();

  while (sched.run_main(10))
    ;

  sched.finish();

  return 0;
}

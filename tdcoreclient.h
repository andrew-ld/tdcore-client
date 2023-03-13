#include "td/actor/impl/Actor-decl.h"
#include "td/actor/impl/ActorId-decl.h"
#include "td/telegram/net/ConnectionCreator.h"
#include "td/telegram/net/DcId.h"
#include "td/telegram/net/NetQuery.h"
#include "td/telegram/net/NetStatsManager.h"
#include "td/telegram/net/Session.h"
#include "td/telegram/OptionManager.h"
#include "td/telegram/TdDb.h"
#include "td/telegram/TdParameters.h"
#include "td/telegram/telegram_api.h"

namespace tdcore {
class TdCoreClient final : public td::Actor {
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

  virtual td::ActorShared<> create_reference(td::uint64 id) final;

 public:
  TdCoreClient(td::TdParameters parameters, td::DcId dc_id, td::unique_ptr<td::TdDb> td_db);

  static void open(td::Promise<td::ActorOwn<TdCoreClient>> promise, td::TdParameters parameters, td::DcId dc_id,
                   td::int32 application_scheduler, td::int32 database_scheduler);

  virtual void perform_network_query(const td::telegram_api::Function &function,
                                     td::Promise<td::NetQueryPtr> promise) final;

  virtual void destroy() final;

  void start_up() final;

  void hangup_shared() final;
};
}  // namespace tdcore

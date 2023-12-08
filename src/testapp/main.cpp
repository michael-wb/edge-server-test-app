////////////////////////////////////////////////////////////////////////////
//
// Copyright 2023 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#include <filesystem>
#include <iostream>
#include <unistd.h>

#include <realm/error_codes.hpp>
#include <realm/object-store/impl/object_accessor_impl.hpp>
#include <realm/object-store/shared_realm.hpp>
#include <realm/object-store/sync/app.hpp>
#include <realm/object-store/sync/async_open_task.hpp>
#include <realm/object-store/sync/sync_manager.hpp>
#include <realm/object-store/sync/sync_session.hpp>
#include <realm/object-store/sync/sync_user.hpp>
#include <realm/object-store/thread_safe_reference.hpp>
#include <realm/util/future.hpp>
#include <realm/util/logger.hpp>

#include <testapp/generic_network_transport.hpp>
#include <testapp/test_data.hpp>

using namespace testapp;
using namespace realm;

std::string get_path()
{
    std::string path = std::filesystem::current_path();
    path += "/data";
    if (!std::filesystem::exists(path)) {
        std::filesystem::create_directory(path);
    }
    return path;
}

auto create_app_config()
{
    app::App::Config app_config;
    app_config.app_id = "devicesync-bmqjg";
    app_config.device_info.sdk = "object-store";
    app_config.device_info.sdk_version = "dev";
    app_config.device_info.platform_version = "7.1";
    app_config.transport = std::make_shared<DefaultTransport>();
    app_config.base_url = "https://realm.mongodb.com";
    return app_config;
}

auto create_sync_config(std::string path,
                        const std::shared_ptr<util::Logger> &logger)
{
    SyncClientConfig sync_config;
    sync_config.metadata_mode = SyncClientConfig::MetadataMode::NoEncryption;
    sync_config.base_file_path = path;
    sync_config.logger_factory =
        [logger = std::move(logger)](util::Logger::Level) -> std::shared_ptr<util::Logger>
    {
        return logger;
    };
    sync_config.log_level = util::Logger::Level::all;
    return sync_config;
}

auto create_realm_config(std::string path,
                         const std::shared_ptr<util::Logger> &logger,
                         const std::shared_ptr<app::App> &app = nullptr) {
    Realm::Config realm_config;
    realm_config.schema_version = 0;
    realm_config.schema = {
        {"Item",
         {Property("_id", PropertyType::ObjectId, Property::IsPrimary(true)),
          Property("summary", PropertyType::String),
          Property("owner_id", PropertyType::String),
          Property("isComplete", PropertyType::Bool)}}};
    logger->info("create_realm_config (app is%1 set)", app ? "" : " not");
    if (app && app->current_user()) {
        realm_config.sync_config = std::make_shared<SyncConfig>(
            app->current_user(), SyncConfig::FLXSyncEnabled{});
        realm_config.sync_config->client_resync_mode = ClientResyncMode::Recover;
    }
    realm_config.path = path + "/realm.qnxdemo";
    logger->info("Using realm path: %1", realm_config.path);
    return realm_config;
}

Status wait_for_upload_completion(const std::shared_ptr<SyncSession> &session,
                                const std::shared_ptr<util::Logger> &logger)
{
    auto [u_promise, u_future] = util::make_promise_future<void>();
    session->wait_for_upload_completion(
        [promise = util::CopyablePromiseHolder<void>(std::move(u_promise)), logger](Status status) mutable {
        if (!status.is_ok()) {
            logger->error("failed to upload: %1", status.reason());
            promise.get_promise().set_error(status);
        }
        promise.get_promise().emplace_value();
    });
    auto result = u_future.get_no_throw();
    return result;
}

Status wait_for_download_completion(const std::shared_ptr<SyncSession> &session,
                                  const std::shared_ptr<util::Logger> &logger)
{
    auto [d_promise, d_future] = util::make_promise_future<void>();
    session->wait_for_download_completion(
        [promise = util::CopyablePromiseHolder<void>(std::move(d_promise)), logger](Status status) mutable {
        if (!status.is_ok()) {
            logger->error("failed to download: %1", status.reason());
            promise.get_promise().set_error(status);
        }
        promise.get_promise().emplace_value();
    });
    auto result = d_future.get_no_throw();
    return result;
}

Status log_in(const std::string& email, const std::string& password,
              const std::shared_ptr<util::Logger> &logger,
              const std::shared_ptr<app::App> &app)
{
    auto [l_promise, l_future] = util::make_promise_future<void>();
    app->log_in_with_credentials(
        realm::app::AppCredentials::username_password(email, password),
        [email, promise = util::CopyablePromiseHolder<void>(std::move(l_promise)), logger](std::shared_ptr<realm::SyncUser> user,
            util::Optional<app::AppError> error) mutable {
        if (error) {
            logger->error("%1: Failed to log in %2: %3",
                            error->code_string(), email, error->reason());
            promise.get_promise().set_error(error->to_status());
            return;
        }
        if (!user) {
            logger->error("error: Failed to log in %1: user is null", email);
            promise.get_promise().set_error({ErrorCodes::UserNotFound, "user is null"});
            return;
        }
        logger->info("User logged in: %1", email);
        promise.get_promise().emplace_value();
    });
    auto result = l_future.get_no_throw();
    return result;
}

bool do_realm_sync(const std::string& email, const std::string& password,
                   const std::shared_ptr<util::Logger> &logger,
                   const std::shared_ptr<app::App> &app)
{
    std::optional<Status> sync_result;
    auto realm_config = create_realm_config(get_path(), logger, app);
    realm_config.sync_config->error_handler =
        [&](std::shared_ptr<SyncSession> session, SyncError error) mutable {
    util::format(std::cerr,
        "An unexpected sync error was caught by the default SyncTestFile handler: '%1' for '%2'",
            error.status, session->path());
        sync_result = error.status;
    };

    int retry_count = 0;
    while(retry_count < 2) {
        Status result = Status::OK();
        sync_result.reset();
        {
            auto realm = Realm::get_shared_realm(realm_config);
            auto session = app->sync_manager()->get_existing_session(realm_config.path);
            if (!session)
            {
                logger->error("Session is null: %1", realm_config.path);
                return false;
            }
            if (!sync_result || sync_result->is_ok()) {
                result = wait_for_download_completion(session, logger);
                if (result.is_ok()) {
                    result = wait_for_upload_completion(session, logger);
                }
            }
        }
        if (result.is_ok() && (!sync_result || sync_result->is_ok())) {
            return true;
        }
        if (result.reason().find("signature is invalid") != std::string::npos || sync_result->code() == ErrorCodes::AuthError) {
            auto login_result = log_in(email, password, logger, app);
            if (!login_result.is_ok()) {
                return false;
            }
        }
        retry_count++;
    }
    return false;
}

bool update_base_url(std::string hostname, const std::shared_ptr<util::Logger> &logger,
                     const std::shared_ptr<app::App> &app)
{
    auto pf = util::make_promise_future<void>();
    app->update_base_url(hostname, [&logger, &app, promise = util::CopyablePromiseHolder<void>(std::move(pf.promise))](util::Optional<app::AppError> error) mutable {
        if (error) {
            promise.get_promise().set_error(error->to_status());
        }
        else {
            logger->debug("BaseURL updated to: %1", app->get_base_url());
            promise.get_promise().emplace_value();
        }
    });
    auto result = pf.future.get_no_throw();
    if (!result.is_ok()) {
        logger->error("%1: Failed to update base_url: %2", hostname);
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    const std::string email = "someone@testapp.com";
    const std::string password = "aewfl;kj98eafelkj";
    const std::string host2 = "https://34.111.234.31.nip.io/device-sync"; // Apigee front end to cloud server
    const std::string host3 = "http://localhost"; // Edge server

    std::shared_ptr<util::Logger> logger =
        std::make_shared<util::StderrLogger>(util::Logger::Level::all);
    util::Logger::set_default_level_threshold(util::Logger::Level::all);
    auto app_config = create_app_config();
    auto sync_config = create_sync_config(get_path(), logger);
    auto app = app::App::get_uncached_app(app_config, sync_config);
    if (auto user = app->sync_manager()->get_current_user(); !user || !user->is_logged_in() ) {
        if (!log_in(email, password, logger, app).is_ok()) {
            logger->error("Trying to create user account...");
            // Try to create the user
            app->provider_client<app::App::UsernamePasswordProviderClient>()
                .register_email(
                    email, password, [&](util::Optional<app::AppError> error)
                    {
                        if (error) {
                            if (error->code() == ErrorCodes::AccountNameInUse) {
                                logger->info("User already exists: %2", error->code_string(),
                                    email);
                            } else {
                                logger->error("%1: Failed to create user: %2",
                                    error->code_string(), error->reason());
                                exit(1);
                            }
                        } else {
                            logger->info("Created user: %1", email);
                        } });
        };
    }
    logger->info("Step 1 - Session1 opened with default base_url: %1", app->get_base_url());
    if (!do_realm_sync(email, password, logger, app)) {
        exit(1);
    }
    if (!update_base_url(host2, logger, app)) {
        exit(1);
    }
    logger->info("Step 2 - session resumed with base_url: %1", app->get_base_url());
    if (!do_realm_sync(email, password, logger, app)) {
        exit(1);
    }
    if (!update_base_url(host3, logger, app)) {
        exit(1);
    }
    logger->info("Step 3 - session resumed with base_url: %1", app->get_base_url());
    if (!do_realm_sync(email, password, logger, app)) {
        exit(1);
    }
}

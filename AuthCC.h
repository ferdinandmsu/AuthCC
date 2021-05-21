#ifndef AUTHCCLIBRARY_AUTHCC_H
#define AUTHCCLIBRARY_AUTHCC_H

#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <thread>
#include <functional>
#include <chrono>
#include <future>

#define CPPHTTPLIB_OPENSSL_SUPPORT

#include "httplib.h"
#include "nlohmann/json.hpp"

#ifdef _WIN32
#define OS_WINDOWS
#elif _WIN64
#define OS_WINDOWS
#else
#define OS_LINUX
#endif

namespace auth {
    namespace details {
        enum class Error {
            SUCCESS,
            INVALID_LICENSE,
            EMAIL_USED,
            INVALID_USERNAME,
            INVALID_HWID,
            INVALID_DETAILS,
            HWID_UPDATED,
            TIME_EXPIRED,
            NOT_INITIALIZED,
            NOT_LOGGEDIN,
            UNKNOWN
        };

        enum class Switch {
            DISABLED,
            ENABLED
        };

        struct User {
            std::string hwid;
            std::string username;
            std::string ip;
            std::string variable;
            std::string expiry_date;
            std::string email;

            unsigned int id;
            int rank;

            friend std::ostream &operator<<(std::ostream &os, const User &user) {
                os << "User(HWID: '" << user.hwid << "', username: '" << user.username << "', "
                   << "ip: '" << user.ip << "', variable: '" << user.variable << "', expiry_date: '"
                   << user.expiry_date << "', rank: " << user.rank << ", id: " << user.id
                   << ", email: '" << user.email << "'" ")";
                return os;
            }
        };

        struct License {
            std::string token;
            std::string used_by;

            bool used;
            int days;
            int rank;

            friend std::ostream &operator<<(std::ostream &os, const License &license) {
                os << std::boolalpha << "License(token: '" << license.token << "', rank: '" << license.rank
                   << "', used: '" << license.used << "', used_by: '" << license.used_by << "', days: '"
                   << license.days << ")";
                return os;
            }
        };

        struct AppInfo {
            Switch status;
            Switch developer_mode;
            Switch download_link;
            Switch free_mode;
            Switch login;
            Switch register_;

            std::string hash;
            std::string version;
            std::string name;

            unsigned long users;

            friend std::ostream &operator<<(std::ostream &os, const AppInfo &info) {
                os << std::boolalpha << "AppInfo(status: " << static_cast<int>(info.status) << ", developermode: "
                   << static_cast<int>(info.developer_mode) << ", download_link: "
                   << static_cast<int>(info.download_link) << ", free_mode: "
                   << static_cast<int>(info.free_mode) << ", login: "
                   << static_cast<int>(info.login) << ", register: "
                   << static_cast<int>(info.register_) << ", hash: '"
                   << info.hash << "', version: " << info.version << ", name: '" << info.name << "', users: "
                   << info.users << ")";
                return os;
            }
        };


        Switch toSwitch(const std::string &str) {
            return str == "Enabled" ? Switch::ENABLED : Switch::DISABLED;
        }

        std::string errorMessage(const Error error) {
            if (error == Error::SUCCESS)
                return "";
            else if (error == Error::UNKNOWN)
                return "Unknown";
            else if (error == Error::NOT_INITIALIZED)
                return "Client is not initialized";
            else if (error == Error::NOT_LOGGEDIN)
                return "Client is not logged in";
            else if (error == Error::TIME_EXPIRED)
                return "The account is expired";
            else if (error == Error::HWID_UPDATED)
                return "Hwid was updated";
            else if (error == Error::INVALID_DETAILS)
                return "Invalid credentails";
            else if (error == Error::INVALID_HWID)
                return "Invalid hwid";
            else if (error == Error::EMAIL_USED)
                return "Email is used";
            else if (error == Error::INVALID_USERNAME)
                return "Invalid username";
            else
                return "Something went wrong while resolving the error";
        }

        std::string exec(const char *cmd) {
            std::array<char, 128> buffer{};
            std::string result;
#ifdef OS_WINDOWS
            std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
#else
            std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
#endif
            if (!pipe) {
                throw std::runtime_error("popen() failed!");
            }
            while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                result += buffer.data();
            }
            return result;
        }

        std::vector<std::string> split(const std::string &str,
                                       const std::string &delimiter) {
            std::vector<std::string> output;
            std::string s = str;

            size_t pos = 0;
            std::string token;
            while ((pos = s.find(delimiter)) != std::string::npos) {
                token = s.substr(0, pos);
                output.push_back(token);
                s.erase(0, pos + delimiter.length());
            }

            output.push_back(s);
            return output;
        }

        std::string strip(const std::string &str,
                          const std::function<bool(const char)> &callback) {
            auto start_it = str.begin();
            auto end_it = str.rbegin();
            while (callback(*start_it) && start_it != end_it.base())
                ++start_it;
            while (callback(*end_it) && start_it != end_it.base())
                ++end_it;
            return std::string(start_it, end_it.base());
        }

        std::string hostname() {
            return strip(exec("hostname"), [](const char c) { return isspace(c); });
        }

        std::string username() {
#ifdef OS_LINUX
            return strip(exec("whoami"), [](const char c) { return isspace(c); });
#else
            return strip(exec("echo %USERNAME%"), [](const char c) {return isspace(c);});
#endif
        }

        std::string getHardwareID() {
            std::string hwid;

#ifdef OS_WINDOWS
            hwid = split(system::exec("wmic csproduct get uuid"), "\n")[1];
#else
            hwid = exec("dmidecode -s system-uuid");
#endif

            return strip(hwid, [](const char c) { return std::isspace(c); });
        }
    }

    class Client {
    public:
        Client(std::string aid, std::string apikey, std::string secret)
                : aid(std::move(aid)), apikey(std::move(apikey)),
                  secret(std::move(secret)), variables({}),
                  hostname(details::hostname()), hwid(details::getHardwareID()),
                  is_initialized(false), is_loggedin(false) {}

        bool init() {
            try {
                auto json = request("info");
                if (!json["result"].is_null() && json["result"].get<std::string>() == "failed")
                    return false;

                parseInfo(json);
                return true;
            }
            catch (...) {
                return false;
            }
        }

        details::Error userLogin(const std::string &username, const std::string &password) {
            if (!is_initialized) return details::Error::NOT_INITIALIZED;

            try {
                auto json = request("login", {{"username", username},
                                              {"password", password}});
                if (json["result"].get<std::string>() == "invalid_details")
                    return details::Error::INVALID_DETAILS;
                else if (json["result"].get<std::string>() == "invalid_hwid")
                    return details::Error::INVALID_HWID;
                else if (json["result"].get<std::string>() == "hwid_updated")
                    return details::Error::HWID_UPDATED;
                else if (json["result"].get<std::string>() == "time_expired")
                    return details::Error::TIME_EXPIRED;
                else if (json["result"].get<std::string>() != "success")
                    return details::Error::UNKNOWN;

                parseUser(json);
                return details::Error::SUCCESS;

            } catch (std::runtime_error &) {
                return details::Error::UNKNOWN;
            }
        }

        details::Error userRegister(const std::string &username,
                                    const std::string &email,
                                    const std::string &password,
                                    const std::string &license) {
            if (!is_initialized) return details::Error::NOT_INITIALIZED;

            try {
                auto json = request("register",
                                    {{"username", username},
                                     {"password", password},
                                     {"email",    email},
                                     {"license",  license}});

                if (json["result"].get<std::string>() == "invalid_license")
                    return details::Error::INVALID_LICENSE;
                else if (json["result"].get<std::string>() == "email_used")
                    return details::Error::EMAIL_USED;
                else if (json["result"].get<std::string>() == "invalid_username")
                    return details::Error::INVALID_USERNAME;
                else if (json["result"].get<std::string>() != "success")
                    return details::Error::UNKNOWN;

                return details::Error::SUCCESS;
            } catch (std::runtime_error &) {
                return details::Error::UNKNOWN;
            }
        }

        details::Error log(const std::string &msg) {
            if (!is_initialized) return details::Error::NOT_INITIALIZED;
            if (!is_loggedin) return details::Error::NOT_LOGGEDIN;

            try {
                auto json = request("log",
                                    {{"action",   msg},
                                     {"pcuser",   hostname},
                                     {"username", user.username}});

                if (json["result"].get<std::string>() != "success")
                    return details::Error::UNKNOWN;

                return details::Error::SUCCESS;
            } catch (std::runtime_error &) {
                return details::Error::UNKNOWN;
            }
        };

        const std::string &getVar(const std::string &key) {
            return variables.at(key);
        }

        [[nodiscard]]
        const details::AppInfo &getInfo() const noexcept {
            return info;
        }

        [[nodiscard]]
        const details::User &getUser() const noexcept {
            return user;
        }

    private:
        void parseInfo(const nlohmann::json &raw) {
            info.status = details::toSwitch(raw["status"]);
            info.free_mode = details::toSwitch(raw["freemode"]);
            info.download_link = details::toSwitch(raw["downloadlink"]);
            info.login = details::toSwitch(raw["login"]);
            info.register_ = details::toSwitch(raw["register"]);
            info.developer_mode = details::toSwitch(raw["developermode"]);

            info.hash = raw["hash"];
            info.version = raw["version"];
            info.name = raw["name"];

            info.users = static_cast<unsigned int>(std::atoi(raw["users"].get<std::string>().c_str()));
            is_initialized = true;
        }

        void parseUser(const nlohmann::json &raw) {
            user.rank = std::atoi(raw["rank"].get<std::string>().c_str());
            user.expiry_date = raw["expiry"];
            user.variable = raw["uservar"];
            user.id = static_cast<unsigned int>(std::atoi(raw["id"].get<std::string>().c_str()));
            user.username = raw["username"];
            user.hwid = raw["hwid"];
            user.ip = raw["ip"];
            user.email = raw["email"];

            variables = raw["variables"].get<std::map<std::string, std::string>>();
            is_loggedin = true;
        }

    private:
        nlohmann::json request(const std::string &type,
                               const std::map<std::string, std::string> &attributes = {}) {
            httplib::SSLClient client{"api.auth.gg"};
            std::string data =
                    "type=" + type + "&aid=" + aid + "&apikey=" + apikey + "&secret=" + secret + "&hwid=" + hwid;

            for (const auto &val : attributes)
                data += "&" + val.first + "=" + val.second;

            auto result = client.Post("/v1/", data, "application/x-www-form-urlencoded");

            if (result.error() != httplib::Error::Success)
                throw std::runtime_error("auth::Client::request() failed!");
            return nlohmann::json::parse(result->body);
        }

    private:
        std::string aid;
        std::string apikey;
        std::string secret;
        std::string hostname;
        std::string hwid;

        std::map<std::string, std::string> variables;
        bool is_initialized;
        bool is_loggedin;

        details::User user;
        details::AppInfo info;
    };
}

#endif

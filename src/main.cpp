#include "../include/AuthCC.h"

int main() {
    auth::Client client("AID",
                        "APIKEY",
                        "SECRET");

    if (client.init()) {
        auto login_result = client.userLogin("moderator1", "pass123");

        if (login_result != auth::details::Error::SUCCESS) {
            std::cout << "Login failed" << std::endl;
            std::cout << "Error: " << auth::details::errorMessage(login_result);
            exit(-1);
        }

    } else {
        std::cout << "Init failed" << std::endl;
    }

    return 0;
}


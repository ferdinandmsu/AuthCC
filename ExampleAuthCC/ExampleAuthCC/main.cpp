#include "AuthCC.h"

int main() {
    auth::Client client("AID",
        "APIKEY",
        "SECRET");

    if (client.init()) {
        auto login_result = client.userLogin("moderator1", "pass123");

        if (login_result != auth::Error::SUCCESS) {
            std::cout << "Error: " << auth::errorMessage(login_result);
            exit(-1);
        }

        std::cout << "SUCCESSFULLY LOGGEDIN!";
        std::cout << client.getUser() << std::endl;

    }
    else {
        std::cout << "Init failed" << std::endl;
    }

	return 0;
}
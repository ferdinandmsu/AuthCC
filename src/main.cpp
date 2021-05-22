#include "../include/AuthCC.h"

int main() {
    // auth client
    auth::Client client("AID",
                        "APIKEY",
                        "SECRET");

    if (client.init()) {
        auth::Error ec; // error code

        // try to register a new user
        ec = client.userRegister("newuser", "mail@mail.com",
                                                   "pass123","LICENSE");
        if (ec != auth::Error::SUCCESS) {
            std::cout << "Error: " << auth::errorMessage(ec);
            exit(-1); // register failed
        }

        if (ec = client.userLogin("newuser", "pass123");
            ec != auth::Error::SUCCESS) {
            std::cout << "Error: " << auth::errorMessage(ec);
            exit(-1); // login failed
        }

        /* SUCCESSFULLY REGISTERED */
        std::cout << "You are logged in!";

        // log message to auth.gg dashboard
        client.log("Hello World");

    } else {
        // initialization failed
        std::cout << "Init failed" << std::endl;
    }

    return 0;
}


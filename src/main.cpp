#include "../include/AuthCC.h"

int main() {
    // auth client
    auth::Client client("AID",
                        "APIKEY",
                        "SECRET");

    if (client.init()) {
        auth::Error ec = client.userLogin("newuser", "pass123");
        std::cout << auth::errorMessage(ec);
    } else {
        // initialization failed
        std::cout << "Init failed" << std::endl;
    }

    return 0;
}



<br />
<p align="center">
  <h3 align="center">AuthCC</h3>

  <p align="center">
    Header only AuthGG api wrapper
    <br />
</p>


## Example

- Login example:
```cpp
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

} else {
    std::cout << "Init failed" << std::endl;
}
```
- Register Example
```cpp
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

        std::cout << "SUCCESSFULLY REGISTERED!";

        // log message to auth.gg dashboard
        client.log("Hello World");

  } else {
    // initialization failed
    std::cout << "Init failed" << std::endl;
  }
  ```

## Features
 
Features:
* Login
* Register
* Reset password
* Forgot password
* Extend subscription
* Works on linux and windows



### Built With

Here are the things it's made with
* [C++](http://cppreference.com)
* [AuthGG](https://auth.gg)



## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
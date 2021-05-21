
<br />
<p align="center">
  <h3 align="center">AuthCC</h3>

  <p align="center">
    Header only AuthGG api wrapper
    <br />
</p>


## Example

```cpp
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
```

## Features
 
Features:
* It is fast
* It is easy to use



### Built With

Here are the things it's made with
* [C++](http://cppreference.com)




## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the GNU License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

Project Link: [https://firey.gg]
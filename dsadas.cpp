#include <iostream>
#include <string>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

int main() {
    std::string secret_hash = "c2543fff3bfa6f144c2f06a7de6cd10c0b650cae5c1a0f2e5e2e5c8fd830324e";
    std::string user_input;

    std::cout << "Welcome to the CrackMe program!" << std::endl;
    std::cout << "Enter the secret code: ";
    std::getline(std::cin, user_input);

    std::string hashed_input = sha256(user_input);

    if (hashed_input == secret_hash) {
        std::cout << "Access granted." << std::endl;
    } else {
        std::cout << "Access denied." << std::endl;
    }

    return 0;
}

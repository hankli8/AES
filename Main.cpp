#include<iostream>
#include<string>
#include<iomanip>
#include"AES.h"
int main() {
	unsigned char dummy[240] = { 0 };
	unsigned char key[240];
	encryption_object e;
	std::string input, encrypted_message, decrypted_message;
	std::getline(std::cin, input);
	encrypted_message = e.encrypt(input, key);
	for (unsigned char i : encrypted_message) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)i;
	}
	decrypted_message = e.decrypt(encrypted_message, dummy);
	std::cout << '\n' << decrypted_message;
}

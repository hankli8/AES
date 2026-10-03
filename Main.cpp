#include<iostream>
#include<string>
#include<iomanip>
#include"AES.h"
int main() {
	unsigned char key[240];
	std::string input, cipher, output;
	std::getline(std::cin, input);
	encryption_object e;
	cipher=e.encrypt(input.c_str());
	for (unsigned char i : cipher)
		std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)i;
	e.get_key(key);
	output = e.decrypt(cipher, key);
	std::cout <<std::endl<< output;
}

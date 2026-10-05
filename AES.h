#pragma once
#include<iostream>
#include<random>
#include<vector>
#include<cstring>
#include<cmath>

unsigned char s_box[256] = 
	{ 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

unsigned char Rcon_values[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

class encryption_object {
private:
	unsigned char round_keys[240] = { 0 };
public:
	unsigned char hash[16] = { 0 };
	unsigned char nonce[12] = { 0 };
	unsigned char current_matrix[4][4];

	int rotword(int index) {
		return (index + 1) % 4;
	}

	int subword(unsigned char value) {
		unsigned char a = value >> 4, b = value & 0x0f;
		return s_box[a * 16 + b];
	}

	int get_key_value(int i, int j, int k) {
		int index_value = 32 + i * 16 + j, w = 8 + 4 * i + j;
		int answer = 0;
		if (w % 8 == 0) {
			answer = round_keys[32 + i * 16 + j * 4 + k - 32] ^ subword(round_keys[32 + i * 16 + j * 4 + rotword(k) - 4]);
			if (k == 0) {
				answer ^= Rcon_values[w / 8];
			}
			return answer;
		}
		else if (w % 8 == 4) {
			answer = round_keys[32 + i * 16 + j * 4 + k - 32] ^ subword(round_keys[32 + i * 16 + j * 4 + k - 4]);
			return answer;
		}
		else {
			answer = round_keys[32 + i * 16 + j * 4 + k - 32] ^ round_keys[32 + i * 16 + j * 4 + k - 4];
			return answer;
		}
	}

	void initialize_keys() {
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<int> distribution(0, 255);
		for (int i = 0;i < 4;i++) {
			for (int j = 0;j < 4;j++) {
				round_keys[j * 4 + i] = distribution(gen);
				round_keys[16 + j * 4 + i] = distribution(gen);
			}
		}
		for (int i = 0;i < 13;i++) {
			for (int j = 0;j < 4;j++) {
				for (int k = 0;k < 4;k++) {
					round_keys[32 + i * 16 + j * 4 + k] = get_key_value(i, j, k);
				}
			}
		}
	}

	void subbytes() {
		for (int i = 0;i < 4;i++) {
			for (int j = 0;j < 4;j++) {
				int row, col;
				row = current_matrix[j][i] >> 4;
				col = current_matrix[j][i] & 0x0f;
				current_matrix[j][i] = s_box[row * 16 + col];
			}
		}
	}

	void shift_rows() {
		unsigned char copy[4][4];
		std::memcpy(copy, current_matrix, 16);
		for (int i = 1;i < 4;i++) {
			for (int j = 0;j < 4;j++) {
				current_matrix[i][j] = copy[i][(j + i) % 4];
			}
		}
	}

	unsigned char shift_left_one(unsigned char a) {
		if (a & 0x80)
			return a << 1 ^ 0x1b;
		else
			return a << 1^0x00;
	}

	unsigned char x(int a, unsigned char b) {
		switch (a) {
		case 2:
			return shift_left_one(b);
			break;
		case 3:
			return shift_left_one(b) ^ b;
			break;
		case 9:
			return shift_left_one(shift_left_one(shift_left_one(b))) ^ b;
			break;
		case 11:
			return shift_left_one(shift_left_one(shift_left_one(b))) ^ shift_left_one(b) ^ b;
			break;
		case 13:
			return shift_left_one(shift_left_one(shift_left_one(b))) ^ shift_left_one(shift_left_one(b)) ^ b;
			break;
		case 14:
			return shift_left_one(shift_left_one(shift_left_one(b))) ^ shift_left_one(shift_left_one(b)) ^ shift_left_one(b);
			break;
		}
	}

	void mix_columns() {
		for(int i=0;i<4;i++){
			unsigned char* original_column[4] = { &current_matrix[0][i], &current_matrix[1][i], &current_matrix[2][i], &current_matrix[3][i] };
			unsigned char new_column[4];
			new_column[0] = x(2, *original_column[0]) ^ x(3, *original_column[1]) ^ *original_column[2] ^ *original_column[3];
			new_column[1] = *original_column[0] ^ x(2, *original_column[1]) ^ x(3, *original_column[2]) ^ *original_column[3];
			new_column[2] = *original_column[0] ^ *original_column[1] ^ x(2, *original_column[2]) ^ x(3, *original_column[3]);
			new_column[3] = x(3, *original_column[0]) ^ *original_column[1] ^ *original_column[2] ^ x(2, *original_column[3]);
			*original_column[0] = new_column[0], * original_column[1] = new_column[1], * original_column[2] = new_column[2], * original_column[3] = new_column[3];
		}
	}
	
	void add_round_key(int round_cnt) {
		for (int i = 0;i < 4;i++) {
			for (int j = 0;j < 4;j++) {
				current_matrix[j][i] = current_matrix[j][i] ^ round_keys[round_cnt * 16 + i * 4 + j];
			}
		}
	}

	void increment() {
		nonce[11]++;
		for (int i = 11;i >= 1;i--) {
			if (nonce[i] == 255) {
				nonce[i]++;
				nonce[i - 1]++;
			}
		}
	}

	void hash_encrypt() {
		std::memset(hash, 0, 16);
		for (int i = 0;i < 16;i++) {
			current_matrix[i % 4][i / 4] = hash[i];
		}
		add_round_key(0);
		for (int i = 1;i < 14;i++) {
			subbytes();
			shift_rows();
			mix_columns();
			add_round_key(i);
		}
		subbytes();
		shift_rows();
		add_round_key(14);
		for (int i = 0;i < 16;i++) {
			hash[i] = current_matrix[i % 4][i / 4];
		}
	}

	void counter_blocks_encrypt(std::vector<std::vector<unsigned char>>& counter_blocks) {
		for (int i = 0;i < counter_blocks.size();i++) {
			for (int j = 0;j < 16;j++) {
				current_matrix[j % 4][j / 4] = counter_blocks[i][j];
			}
			add_round_key(0);
			for (int j = 1;j < 14;j++) {
				subbytes();
				shift_rows();
				mix_columns();
				add_round_key(j);
			}
			subbytes();
			shift_rows();
			add_round_key(14);
			for (int j = 0;j < 16;j++) {
				counter_blocks[i][j] = current_matrix[j % 4][j / 4];
			}
		}
	}

	void xor_copy(std::vector<unsigned char>& result, unsigned char* copy) {
		for (int i = 0;i < result.size();i++) {
			result[i] ^= *(copy + i);
		}
	}

	void shift_copy(unsigned char* copy) {
		bool true_bit_fell= false, carry_over=false, next_carry_over=false;
		if (*(copy + 15) & 0x01) {
			true_bit_fell = true;
		}
		if (*copy & 0x01) {
			next_carry_over = true;
		}
		*copy = *copy >> 1;
		for (int i = 1;i < 16;i++) {
			carry_over = next_carry_over;
			next_carry_over = false;
			if (*(copy + i) & 0x01) {
				next_carry_over = true;
			}
			*(copy + i)=*(copy+i) >> 1;
			if (carry_over) {
				*(copy + i) =*(copy+i)|0x80;
				carry_over = false;
			}
		}
		if (true_bit_fell) {
			*(copy) ^= 0xe1;
		}
	}

	std::vector<unsigned char> ghash(std::vector<std::vector<unsigned char>> &counter_blocks, unsigned long long input_length) {
		std::vector<unsigned char> y(16);
		for (int i = 1;i < counter_blocks.size();i++) {
			for (int j = 0;j < 16;j++) {
				y[j] ^= counter_blocks[i][j]; 
			}
			unsigned char copy[16];
			std::vector<unsigned char> result(16);
			std::memcpy(copy, hash, 16);
			for (int j = 0;j < 128;j++) {
				int shift_pos = 7 - j % 8;
				if ((y[j / 8] >> shift_pos) & 0x01) {
					xor_copy(result, copy);
				}
				shift_copy(copy);
			}
			y = result;
		}
		std::vector<unsigned char> length_block(16);
		for (int i = 0;i < 8;i++) {
			length_block[i] = 0;
		}
		length_block[8] = input_length >> 56, length_block[9] = input_length >> 48 & 0xff, length_block[10] = input_length >> 40 & 0xff, length_block[11] = input_length >> 32 & 0xff,
		length_block[12] = input_length >> 24 & 0xff, length_block[13] = input_length >> 16 & 0xff, length_block[14] = input_length >> 8 & 0xff, length_block[15] = input_length & 0xff;
		unsigned char copy[16];
		std::vector<unsigned char> result(16);
		std::memcpy(copy, hash, 16);
		for (int j = 0;j < 16;j++) {
			y[j] ^= length_block[j];
		}
		for (int j = 0;j < 128;j++) {
			int shift_pos = 7 - j % 8;
			if ((y[j / 8] >> shift_pos) & 0x01) {
				xor_copy(result, copy);
			}
			shift_copy(copy);
		}
		y = result;
		return y;
	}

	bool compare_tag(std::vector<unsigned char> tag1, std::vector<unsigned char> tag2) {
		bool same = true;
		std::vector<unsigned char> combined_tag(16);
		for (int i = 0;i < 16;i++) {
			same&=~(tag1[i] ^ tag2[i]);
		}
		return same;
	}

	std::vector<unsigned char> get_counter_block(unsigned char* nonce, unsigned long long counter) {
		std::vector<unsigned char> output;
		for (int i = 0;i < 12;i++) {
			output.push_back(*(nonce + i));
		}
		output.push_back(counter >> 24);
		output.push_back(counter >> 16&0xff);
		output.push_back(counter >> 8&0xff);
		output.push_back(counter & 0xff);
		return output;
	}

	std::string encrypt(std::string input, unsigned char* user_key) {
		std::string encrypted_string = "";
		initialize_keys();
		hash_encrypt();
		increment();
		unsigned long long needed_blocks = std::ceil((double)input.length() / 16.0f) + 1, counter = 1, input_length=input.length();
		std::vector<std::vector<unsigned char>> counter_blocks(needed_blocks, std::vector<unsigned char>(16));
		std::vector<unsigned char> ghash_result(16);
		std::vector<unsigned char> tag(16);
		counter_blocks[0]=get_counter_block(nonce, counter);
		counter++;
		for (int i = 1;i < needed_blocks;i++) {
			counter_blocks[i] = get_counter_block(nonce, counter);
			counter++;
		}
		counter_blocks_encrypt(counter_blocks);
		for (int i = 0;i < input_length;i++) {
			counter_blocks[i/16+1][i%16] ^= input[i];
		}
		for (int i = input_length;i < (counter_blocks.size() - 1) * 16;i++) {
			counter_blocks[counter_blocks.size() - 1][i%16] = 0;
		}
		ghash_result = ghash(counter_blocks, input_length*8);
		for (int i = 0;i < 16;i++) {
			tag[i] = ghash_result[i] ^ counter_blocks[0][i];
		}
		for (int i = 0;i < 12;i++) {
			encrypted_string.push_back(nonce[i]);
		}
		for (int i = 16;i < input_length+16;i++) {
			encrypted_string.push_back(counter_blocks[i / 16][i % 16]);
		}
		for (int i = 0;i < 16;i++) {
			encrypted_string.push_back(tag[i]);
		}
		std::memcpy(user_key, round_keys, 240);
		return encrypted_string;
	}

	std::string decrypt(std::string encrypted_string, unsigned char* key) {
		std::string decrypted_message = "";
		std::memcpy(round_keys, key, 240);
		unsigned long long cipher_text_length = encrypted_string.length() - 28;
		std::vector<unsigned char> tag(16);
		std::vector<unsigned char> calculated_tag(16);
		for (int i = 0;i < 12;i++) {
			nonce[i] = encrypted_string[i];
		}
		for (int i = 12 + cipher_text_length;i < encrypted_string.length();i++) {
			tag[i - 12 - cipher_text_length] = encrypted_string[i];
		}
		hash_encrypt();
		unsigned long long needed_blocks = std::ceil((double)cipher_text_length / 16.0f) + 1, counter = 1;
		std::vector<std::vector<unsigned char>> counter_blocks(needed_blocks, std::vector<unsigned char>(16));
		std::vector<std::vector<unsigned char>> cipher_blocks(needed_blocks, std::vector<unsigned char>(16));
		std::vector<unsigned char> ghash_result(16);
		counter_blocks[0] = get_counter_block(nonce, counter);
		counter++;
		for (int i = 1;i < needed_blocks;i++) {
			counter_blocks[i] = get_counter_block(nonce, counter);
			counter++;
		}
		counter_blocks_encrypt(counter_blocks);
		for (int i = 0;i < cipher_text_length;i++) {
			cipher_blocks[i / 16 + 1][i % 16] = encrypted_string[12 + i];
		}
		ghash_result = ghash(cipher_blocks, cipher_text_length * 8);
		for (int i = 0;i < 16;i++) {
			calculated_tag[i] = ghash_result[i] ^ counter_blocks[0][i]; //might need to change to cipher_block[0][i]
		}
		if (!compare_tag(tag, calculated_tag)) {
			return "tag wrong";
		}
		for (int i = 0;i < cipher_text_length;i++) {
			decrypted_message.push_back(encrypted_string[12 + i] ^ counter_blocks[i / 16 + 1][i % 16]);
		}
		return decrypted_message;
	}
};
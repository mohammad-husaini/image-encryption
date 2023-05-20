#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include<bitset>
#include <iostream>
#include <string>
#include<unordered_map>
#include <opencv2/opencv.hpp>
#include <chrono>

using namespace cv;
using namespace std;
using namespace std::chrono;
using namespace CryptoPP;

string garbageDir = "C:\\Users\\omga\\Desktop\\file2\\Garbage_Data.bmp";
vector<SecByteBlock> keys;

void createMap(unordered_map<string, char>* um) {
	(*um)["0000"] = '0';
	(*um)["0001"] = '1';
	(*um)["0010"] = '2';
	(*um)["0011"] = '3';
	(*um)["0100"] = '4';
	(*um)["0101"] = '5';
	(*um)["0110"] = '6';
	(*um)["0111"] = '7';
	(*um)["1000"] = '8';
	(*um)["1001"] = '9';
	(*um)["1010"] = 'A';
	(*um)["1011"] = 'B';
	(*um)["1100"] = 'C';
	(*um)["1101"] = 'D';
	(*um)["1110"] = 'E';
	(*um)["1111"] = 'F';
}

string hex_str_to_bin_str(string bin) {
	int l = bin.size();
	int t = bin.find_first_of('.');
	int len_left = t != -1 ? t : l;
	for (int i = 1; i <= (4 - len_left % 4) % 4; i++)
		bin = '0' + bin;
	if (t != -1) {
		int len_right = l - len_left - 1;
		for (int i = 1; i <= (4 - len_right % 4) % 4; i++)
			bin = bin + '0';
	}
	unordered_map<string, char> bin_hex_map;
	createMap(&bin_hex_map);

	int i = 0;
	string hex = "";

	while (1) {
		hex += bin_hex_map[bin.substr(i, 4)];
		i += 4;
		if (i == bin.size())
			break;
		if (bin.at(i) == '.')
		{
			hex += '.';
			i++;
		}
	}
	return hex;
}

string getRC4_128(int key) {
	int* key_RC4 = new int[125000];
	key_RC4[0] = key;
	int s[256];
	int t[256];
	for (int i = 0; i < 256; i++) {
		s[i] = i;
		t[i] = key_RC4[i % (1)];
	}
	int temp = 0;
	for (int i = 0; i < 256; i++) {
		temp = (temp + s[i] + t[i]) % 256;
		swap(s[i], s[temp]);
	}
	int i = 0;
	int j = 0;
	int c = 0;
	while (c < 125000) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		swap(s[i], s[j]);
		int temp1 = (s[i] + s[j]) % 256;
		key_RC4[c] = temp1;
		c++;
	}
	int* aray_binary = new int[1000000];
	bitset<8> bit1;
	int eight = 0;
	for (int i = 0; i < 125000; i++) {
		bit1 = key_RC4[i];
		for (int j = 0; j < 8; j++) {
			aray_binary[j + eight] = bit1[j];
		}
		eight = eight + 8;
	}
	string str = "";
	for (int i = 0; i < 128; i++) {
		str += to_string(aray_binary[i]);
	}
	return str;
}

SecByteBlock generateNewKey() {
	string str = hex_str_to_bin_str(getRC4_128(rand()));
	SecByteBlock key((const byte*)str.data(), str.size());
	keys.push_back(key);
	return key;
}
	
char* convert(string str) {
	int size = str.size();
	char* cc = new char[size];
	for (int i = 0; i < size; i++) {
		cc[i] = str[i];
	}
	return cc;
}

string encrypt(string plain, SecByteBlock key, SecByteBlock iv) {
	string cipher;
	try {
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);
		StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher))); // StringSource
	}
	catch (const CryptoPP::Exception& e) {
		cipher = e.what();
		exit(1);
	}
	return cipher;
}

string decrypt(string cipher, SecByteBlock key, SecByteBlock iv) {
	string plain;
	try {
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);
		StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(plain))); // StringSource
	}
	catch (const CryptoPP::Exception& e) {
		plain = e.what();
		exit(1);
	}
	return plain;
}

void copyEncryptedData(string org, string dist) {
	std::ifstream ifs(org, std::ios::binary);
	std::ofstream ofs(dist, std::ios::binary);
	char buffer[144];
	while (ifs.read(buffer, 144)) {
		ofs.write(buffer, 144);
	}
	ofs.write(buffer, 144);
	ofs.close();
}

void copyDecryptedData(string org, string dist) {
	std::ifstream ifs(org, std::ios::binary);
	std::ofstream ofs(dist, std::ios::binary);
	char buffer[128];
	while (ifs.read(buffer, 128)) {
		ofs.write(buffer, 128);
	}
	ofs.write(buffer, 128);
	ofs.close();
}

void encPic(SecByteBlock iv, string org, string& msg) {
	auto start = std::chrono::high_resolution_clock::now();
	std::ifstream ifs(org, std::ios::binary);
	std::ofstream ofs(garbageDir, std::ios::binary);

	char bf[112];
	char buffer[128]; // The size of the block we'll read from the original image and encrypt each time
	char cipherBuffer[144]; // The size of the ciphertext we obtained from the plaintext (original image)

	ifs.read(bf, 112); // The header is 112 bits
	ofs.write(bf, 112);
	int counter = 0;
	while (ifs.read(buffer, sizeof(buffer))) { // Reads 128 bits from image each time and puts it in the buffer
		if ((counter % 8) == 0) generateNewKey();
		string plain = "";
		for (int i = 0; i < 128; i++) { // Converts the character array to string, So the encryption function can do it's job
			plain += buffer[i];
		}
		string cipher = encrypt(plain, keys.at(counter / 8), iv); // Obtaining the ciphertext from the plaintext we got from the image
		for (int i = 0; i < 144; i++) { // Converting the string to array of characters again since ofs.write accepts
										//only character array as first argument
			cipherBuffer[i] = cipher[i];
		}
		ofs.write(cipherBuffer, 144); // Writing the ciphertext to the image (Old block size is 128, New block size is normally 144)
		counter++;
	}
	ofs.write(cipherBuffer, 144);
	ofs.close();
	auto finish = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> elapsed = finish - start;
	copyEncryptedData(garbageDir, org); // Move the data stored in garbage file to our original file
	remove("C:\\Users\\omga\\Desktop\\file2\\Garbage_Data.bmp"); // Get rid of the garbage file after moving it's data to the original file
	msg = "Image Encrypted Succesully! (Execution time: " + to_string(elapsed.count()) + ")";
}

void decPic(SecByteBlock iv, string org, string& msg) {
	char bf[112];
	char buffer[128];
	char cipherBuffer[144];
	std::ifstream ifs(org, std::ios::binary);
	std::ofstream ofs(garbageDir, std::ios::binary);
	int counter = 0;
	ifs.read(bf, 112); // The header is 112 bits
	ofs.write(bf, 112);
	while (ifs.read(cipherBuffer, sizeof(cipherBuffer))) {
		string cipher = "";
		for (int i = 0; i < 144; i++) {
			cipher += cipherBuffer[i];
		}
		string plain = decrypt(cipher, keys.at(counter / 8), iv);
		for (int i = 0; i < 128; i++) {
			buffer[i] = plain[i];
		}
		ofs.write(buffer, 128);
		counter++;
	}
	ofs.write(buffer, 128);
	ofs.close();
	copyDecryptedData(garbageDir, org);
	remove("C:\\Users\\omga\\Desktop\\file2\\Garbage_Data.bmp");
	msg = "Image Decrypted Succesully! (Execution time: ";
}

string getSelectMenu(string& msg, bool clear) {
		if (clear) system("cls");
	string str = "| 1) Encrypt the selected Image\n"
		"| 2) Decrypt the selected Image\n"
		"| 3) Change Image directory\n"
		"| 4) Show the Image\n\n| " +
		msg +
		"\n| >> ";
	msg = "Please select value (1-4)";
	return str;
}

void changeDirectory(string& msg, string& dir) {
		system("cls");
	cout << "| Enter the new directory" << endl;
	cout << " >> ";
	cin >> dir;
	msg = "Directory changed to: " + dir;
}

int main() {
	HexEncoder encoder(new FileSink(cout));
	AutoSeededRandomPool prng;
	SecByteBlock iv(AES::BLOCKSIZE);
	prng.GenerateBlock(iv, iv.size());
	string dir = "C:\\Users\\omga\\Desktop\\file2\\lena_color.bmp";
	int sel;
	string msg = "Please select value (1-4)";
	bool clear = true;
	while (1) {
		cout << getSelectMenu(msg, clear);
		while (cin >> sel && (sel < 1 || sel > 6)) {
			cout << getSelectMenu(msg, clear);
		}
		clear = true;
		auto start = std::chrono::high_resolution_clock::now();
		auto finish = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> elapsed = finish - start;
		switch (sel) {
		case 1:
			start = std::chrono::high_resolution_clock::now();
			encPic(iv, dir, msg);
			finish = std::chrono::high_resolution_clock::now();
			elapsed = finish - start;
			break;
		case 2:
			start = std::chrono::high_resolution_clock::now();
			decPic(iv, dir, msg);
			finish = std::chrono::high_resolution_clock::now();
			elapsed = finish - start;
			break;
		case 3:
			changeDirectory(msg, dir);
			break;
		case 4:
		{
			Mat image = imread("C:\\Users\\omga\\Desktop\\file2\\lena_color.bmp");

			// Check for failure
			if (image.empty())
			{
				cout << "Could not open or find the image" << endl;
				cin.get();
				return -1;
			}

			String windowName = "Image Explorer";

			namedWindow(windowName);

			imshow(windowName, image);

			waitKey(0);


		}
		break;
		default:
			break;
		}
	}
	system("pause");
	return 0;
}
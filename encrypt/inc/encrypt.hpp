#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <string>

namespace encrypt
{
	// Function to compute SHA-256 hash of a string
	std::string sha256(const std::string &input)
	{
		unsigned char hash[SHA256_DIGEST_LENGTH]; // 32 bytes
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, input.c_str(), input.size());
		SHA256_Final(hash, &sha256);

		// Convert to hexadecimal string
		std::stringstream ss;
		for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
		{
			ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
		}
		return ss.str();
	}
} // namespace encrypt
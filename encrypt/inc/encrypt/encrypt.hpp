#include <chrono>
#include <cstddef>
#include <cstring>
#include <net/buffer_container.hpp>
#include <openssl/evp.h>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace encrypt
{
	template <typename T>
	std::string get_sha256_from_buffer(const T &input)
	    requires net::BufferContainer<T>
	{
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		if (!ctx)
		{
			throw std::runtime_error("Failed to create EVP_MD_CTX");
		}

		if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
		    EVP_DigestUpdate(ctx, input.data(), input.size()) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("Failed to compute SHA-256 hash");
		}

		unsigned int digest_len = EVP_MD_size(EVP_sha256()); // 32 for SHA-256
		std::vector<char> hash(digest_len);

		if (EVP_DigestFinal_ex(ctx,
		                       reinterpret_cast<unsigned char *>(hash.data()),
		                       &digest_len) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("Failed to finalize SHA-256 hash");
		}

		EVP_MD_CTX_free(ctx);

		// Convert hash to hex string
		std::stringstream ss;
		for (unsigned char c : std::span<const char>(hash.data(), digest_len))
		{
			ss << std::hex << std::setw(2) << std::setfill('0')
			   << (static_cast<unsigned int>(static_cast<unsigned char>(c)));
		}

		return ss.str();
	}

	inline std::vector<char> generate_random_bytes(std::size_t size)
	{
		std::vector<char> buffer(size + 8);

		uint64_t now_ns =
		    std::chrono::duration_cast<std::chrono::nanoseconds>(
		        std::chrono::steady_clock::now().time_since_epoch())
		        .count();

		std::memcpy(buffer.data(), &now_ns, sizeof(now_ns));

		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<unsigned short> dist(0, 255);

		for (std::size_t i = 8; i < buffer.size(); ++i)
		{
			buffer[i] = static_cast<char>(dist(gen));
		}

		return buffer;
	}

	inline std::string generate_random_sha256_string(std::size_t size)
	{
		return get_sha256_from_buffer(generate_random_bytes(size));
	}
} // namespace encrypt
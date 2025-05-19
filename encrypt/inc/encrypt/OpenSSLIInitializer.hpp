#ifndef OPENSSL_INITIALIZER_H
#define OPENSSL_INITIALIZER_H

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
namespace encrypt
{
	class OpenSSLInitializer
	{
	public:
		OpenSSLInitializer()
		{
			static bool initialized = false;
			if (!initialized)
			{
				SSL_library_init();
				OpenSSL_add_all_algorithms();
				SSL_load_error_strings();
				initialized = true;
			}
		}
	};
} // namespace encrypt
#endif // OPENSSL_INITIALIZER_H

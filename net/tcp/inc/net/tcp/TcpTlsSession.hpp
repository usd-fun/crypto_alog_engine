#ifndef NET_TCP_TCP_TLS_CLIENT_H
#define NET_TCP_TCP_TLS_CLIENT_H

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <encrypt/OpenSSLIInitializer.hpp>
#include <limits>
#include <net/buffer_container.hpp>
#include <net/error.hpp>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <span>
#include <string>
#include <sys/socket.h>
#include <tuple>
#include <unistd.h>
#include <vector>

namespace net
{
	namespace tcp
	{
		class TcpTlsSession
		{
		public:
			enum class TcpSessionStatus : unsigned int
			{
				SESSION_DISCONNECTED = 0,
				SESSION_SOCKET_CONNECTING = 1,
				SESSION_TSL_CONNECTING = 2,
				SESSION_CONNECTED = 3
			};

		public:
			TcpTlsSession(std::size_t read_buffer_size = 1048576,
			              std::size_t write_buffer_size = 1048576,
			              bool auto_connect = true)
			    : _ctx(nullptr)
			    , _ssl(nullptr)
			    , _read_buffer()
			    , _write_buffer()
			    , _hostname("")
			    , _status(TcpSessionStatus::SESSION_DISCONNECTED)
			    , _port(0)
			    , _socket_fd(-1)
			    , _connected(false)
			    , _auto_connect(auto_connect)
			{
				SSL_library_init();
				OpenSSL_add_all_algorithms();
				SSL_load_error_strings();
				_ctx = SSL_CTX_new(TLS_client_method());
				_read_buffer.reserve(read_buffer_size);
				_write_buffer.reserve(write_buffer_size);
				_read_buffer.resize(0);
				_write_buffer.resize(0);
			}

			~TcpTlsSession()
			{
				disconnect();
				if (_ctx)
					SSL_CTX_free(_ctx);
			}

			net::NetError connect(const std::string &hostname, int port)
			{
				_hostname = hostname;
				_port = port;
				if (_connected)
					disconnect();
				auto ret = do_connect();
				_connected = (ret == net::NetError::ERR_OK);
				return ret;
			}

			net::NetError connect(const std::string &host_port)
			{
				auto pos = host_port.rfind(':');
				if (pos == std::string::npos)
				{
					return net::NetError::ERR_NET_URL_INVALID;
				}
				auto hostname = host_port.substr(0, pos);
				auto port_str = host_port.substr(pos + 1);
				char *endptr = nullptr;
				long port_num = std::strtol(port_str.c_str(), &endptr, 10);
				if (*endptr != '\0' || port_num <= 0 || port_num > 65535)
				{
					return net::NetError::ERR_NET_PORT_INVALID;
				}
				auto port = static_cast<int>(port_num);
				return connect(hostname, port);
			}

			void disconnect()
			{
				_connected = false;
				if (_ssl)
				{
					SSL_shutdown(_ssl);
					SSL_free(_ssl);
					_ssl = nullptr;
				}
				if (_socket_fd >= 0)
				{
					::close(_socket_fd);
					_socket_fd = -1;
				}
				_read_buffer.resize(0);
				_write_buffer.resize(0);
			}

			bool is_connected() const { return _connected; }

			template <typename T>
			net::NetError send(const T &data)
			    requires net::BufferContainer<T>
			{
				auto buffer_size = _write_buffer.size();
				auto buffer_ptr = _write_buffer.data();
				auto data_size = data.size();
				auto ptr = data.data();
				if (0 != buffer_size)
				{
					auto snd_rt = do_send(_write_buffer);
					auto sent_error = std::get<0>(snd_rt);
					auto rest_size = std::get<1>(snd_rt);
					if (net::NetError::ERR_OK != sent_error)
						return sent_error;
					else if (0 != rest_size)
					{
						auto had_send = buffer_size - rest_size;
						std::memmove(buffer_ptr, buffer_ptr + had_send,
						             rest_size);
						_write_buffer.resize(rest_size);
						return net::NetError::ERR_OK;
					}
				}
				auto snd_rt = do_send(data);
				auto sent_error = std::get<0>(snd_rt);
				auto rest_size = std::get<1>(snd_rt);
				if (net::NetError::ERR_OK != sent_error)
					return sent_error;
				else if (0 != rest_size)
				{
					auto new_size = buffer_size + rest_size;
					_write_buffer.resize(new_size);
					auto had_send = data_size - rest_size;
					std::memcpy(buffer_ptr + buffer_size, ptr + had_send,
					            rest_size);
				}
				return net::NetError::ERR_OK;
			}

			net::NetError send(const char *str)
			{
				std::span<const char> data(str, std::strlen(str));
				return send(data);
			}

			ssize_t recv(void *buffer, size_t len)
			{
				int ret = SSL_read(_ssl, buffer, static_cast<int>(len));
				if (ret <= 0)
				{
					int err = SSL_get_error(_ssl, ret);
					if (err == SSL_ERROR_ZERO_RETURN)
					{
						_connected = false;
						if (_auto_connect)
							reconnect();
						return 0;
					}
					if (is_fatal_error(err))
						if (_auto_connect)
							reconnect();
					return -1;
				}
				return ret;
			}

		private:
			SSL_CTX *_ctx;
			SSL *_ssl;
			std::vector<char> _read_buffer;
			std::vector<char> _write_buffer;
			std::string _hostname;
			TcpSessionStatus _status;
			int _port;
			int _socket_fd;
			bool _connected;
			bool _auto_connect;

			bool is_fatal_error(int _ssl_err)
			{
				return !(_ssl_err == SSL_ERROR_WANT_READ ||
				         _ssl_err == SSL_ERROR_WANT_WRITE);
			}

			net::NetError do_connect()
			{
				if (_ssl)
				{
					SSL_shutdown(_ssl);
					SSL_free(_ssl);
					_ssl = nullptr;
				}
				if (_socket_fd >= 0)
				{
					::close(_socket_fd);
					_socket_fd = -1;
				}
				struct addrinfo hints = {}, *res = nullptr;
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;

				int err =
				    ::getaddrinfo(_hostname.c_str(),
				                  std::to_string(_port).c_str(), &hints, &res);
				if (err != 0 || !res)
					return static_cast<net::NetError>(err);
				_socket_fd = ::socket(res->ai_family, res->ai_socktype,
				                      res->ai_protocol);
				if (_socket_fd < 0)
				{
					freeaddrinfo(res);
					return static_cast<net::NetError>(_socket_fd);
				}
				auto connect_ret =
				    ::connect(_socket_fd, res->ai_addr, res->ai_addrlen);
				if (connect_ret < 0)
				{
					::close(_socket_fd);
					_socket_fd = -1;
					freeaddrinfo(res);
					return static_cast<net::NetError>(connect_ret);
				}
				freeaddrinfo(res);

				_ssl = SSL_new(_ctx);
				if (!_ssl)
				{
					::close(_socket_fd);
					_socket_fd = -1;
					auto err = ERR_get_error();
					return static_cast<net::NetError>(err);
				}
				if (!SSL_set_fd(_ssl, _socket_fd))
				{
					SSL_free(_ssl);
					_ssl = nullptr;
					::close(_socket_fd);
					auto err = ERR_get_error();
					return static_cast<net::NetError>(err);
				}
				if (!SSL_set_tlsext_host_name(_ssl, _hostname.c_str()))
				{
					SSL_free(_ssl);
					_ssl = nullptr;
					::close(_socket_fd);
					auto err = ERR_get_error();
					return static_cast<net::NetError>(err);
				}
				int ret = SSL_connect(_ssl);
				if (ret <= 0)
				{
					SSL_free(_ssl);
					_ssl = nullptr;
					::close(_socket_fd);
					_socket_fd = -1;
					auto err = SSL_get_error(_ssl, ret);
					return static_cast<net::NetError>(err);
				}
				return net::NetError::ERR_OK;
			}

			void reconnect()
			{
				disconnect();
				auto ret = do_connect();
				_connected = (ret == net::NetError::ERR_OK);
			}

			std::tuple<net::NetError, int> do_send(const char *data, int len)
			{
				int ret = SSL_write(_ssl, static_cast<const void *>(data), len);
				if (ret <= 0)
				{
					int err = SSL_get_error(_ssl, ret);
					if (is_fatal_error(err))
					{
						if (_auto_connect)
							reconnect();
					}
					return {static_cast<net::NetError>(err), 0};
				}
				return {net::NetError::ERR_OK, 0};
			}

			template <typename T>
			std::tuple<net::NetError, std::size_t> do_send(const T &data)
			    requires net::BufferContainer<T>
			{
				const static auto max_int = std::numeric_limits<int>::max();
				std::size_t had_snd = 0;
				auto snd_cnt = data.size() / max_int + 1;
				auto last_snd = data.size() % max_int;
				auto ptr = data.data();
				for (std::size_t i = 0; i < snd_cnt; ++i)
				{
					int should_send =
					    i != snd_cnt - 1 ? max_int : static_cast<int>(last_snd);
					auto snd_rt = do_send(ptr, should_send);
					auto sent_error = std::get<0>(snd_rt);
					auto sent_size = std::get<1>(snd_rt);
					if (net::NetError::ERR_OK != sent_error)
						return {sent_error, 0};
					if (sent_size == should_send)
					{
						ptr += should_send;
						had_snd += should_send;
					}
					else
						return {net::NetError::ERR_OK,
						        data.size() - had_snd - sent_size};
				}
				return {net::NetError::ERR_OK, 0};
			}
		};
	} // namespace tcp
} // namespace net

#endif // NET_TCP_TCP_TLS_CLIENT_H

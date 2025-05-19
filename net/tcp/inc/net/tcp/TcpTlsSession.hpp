#ifndef NET_TCP_TCP_TLS_SESSION_H
#define NET_TCP_TCP_TLS_SESSION_H

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <encrypt/OpenSSLIInitializer.hpp>
#include <encrypt/encrypt.hpp>
#include <fcntl.h>
#include <functional>
#include <limits>
#include <net/buffer_container.hpp>
#include <net/error.hpp>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <span>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace net
{
	namespace tcp
	{
		class TcpTlsSession
		{
		private:
			int set_nonblocking(int fd)
			{
				int flags = fcntl(fd, F_GETFL, 0);
				if (flags == -1)
					return -1;
				return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
			}

		private:
			class write_node
			{
			public:
				std::vector<char> _data;
				std::string _write_id;
				std::size_t _offer_set;
				write_node() : _data(), _write_id(""), _offer_set(0) {}
			};

		private:
			const static encrypt::OpenSSLInitializer _ssl_initialize;

		private:
			using ErrorCodeCallBack = std::function<void(net::NetError)>;

		public:
			using OnConnectedCallBack = std::function<void()>;
			using OnDisConnectedCallBack = std::function<void()>;
			using OnSendCallBack = std::function<void(const std::string &)>;
			using OnDataCallBack =
			    std::function<void(const std::span<const char> &)>;
			using OnErrorCallBack = std::function<void(net::NetError)>;

		public:
			enum class TcpSessionStatus : unsigned int
			{
				SESSION_IDLE = 0,
				SESSION_DISCONNECTED = 1,
				SESSION_SOCKET_CONNECTING = 2,
				SESSION_TSL_CONNECTING = 3,
				SESSION_CONNECTED = 4,
				SESSION_SHUTING_DOWN_SSH = 5
			};

		public:
			TcpTlsSession(
			    OnConnectedCallBack &&on_connected = []() {},
			    OnDisConnectedCallBack &&on_disconnected = []() {},
			    OnSendCallBack &&on_sent = [](const std::string &) {},
			    OnDataCallBack &&on_data = [](const std::span<const char> &) {},
			    OnErrorCallBack &&on_error = [](net::NetError) {},
			    std::size_t read_buffer_size = 4096, bool auto_connect = true)
			    : _on_connected(std::move(on_connected))
			    , _on_disconnected(std::move(on_disconnected))
			    , _on_sent(std::move(on_sent))
			    , _on_data(std::move(on_data))
			    , _on_error(std::move(on_error))
			    , _ctx(nullptr)
			    , _ssl(nullptr)
			    , _read_buffer()
			    , _write_queue()
			    , _hostname("")
			    , _status(TcpSessionStatus::SESSION_DISCONNECTED)
			    , _port(0)
			    , _socket_fd(-1)
			    , _auto_connect(auto_connect)
			{
				_ctx = SSL_CTX_new(TLS_client_method());
				_read_buffer.resize(read_buffer_size >
				                            std::numeric_limits<int>::max()
				                        ? std::numeric_limits<int>::max()
				                        : read_buffer_size);
			}

			~TcpTlsSession()
			{
				disconnect();
				if (_ctx)
					SSL_CTX_free(_ctx);
			}

			void poll()
			{
				switch (_status)
				{
				case TcpTlsSession::TcpSessionStatus::SESSION_IDLE:
					return;
				case TcpTlsSession::TcpSessionStatus::SESSION_DISCONNECTED:
				{
					do_connect();
					return;
				}
				case TcpTlsSession::TcpSessionStatus::SESSION_SOCKET_CONNECTING:
				{
					do_check_socket_connecting();
					return;
				}
				case TcpTlsSession::TcpSessionStatus::SESSION_TSL_CONNECTING:
				{
					do_check_tls_connecting();
					return;
				}
				case TcpTlsSession::TcpSessionStatus::SESSION_CONNECTED:
				{
					try_send_all_buffer();
					do_read();
					return;
				}
				case TcpTlsSession::TcpSessionStatus::SESSION_SHUTING_DOWN_SSH:
				{
					do_disconnect();
					return;
				}
				default:
					return;
				}
			}

			void connect(const std::string &hostname, int port)
			{
				_hostname = hostname;
				_port = port;
				if (_status != TcpTlsSession::TcpSessionStatus::SESSION_IDLE &&
				    _status !=
				        TcpTlsSession::TcpSessionStatus::SESSION_DISCONNECTED)
				{
					disconnect();
					if (_status == TcpTlsSession::TcpSessionStatus::
					                   SESSION_SHUTING_DOWN_SSH)
						return;
				}
				do_connect();
				return;
			}

			void connect(const std::string &host_port)
			{
				auto pos = host_port.rfind(':');
				if (pos == std::string::npos)
				{
					_on_error(net::NetError::ERR_NET_URL_INVALID);
				}
				auto hostname = host_port.substr(0, pos);
				auto port_str = host_port.substr(pos + 1);
				char *endptr = nullptr;
				long port_num = std::strtol(port_str.c_str(), &endptr, 10);
				if (*endptr != '\0' || port_num <= 0 || port_num > 65535)
				{
					_on_error(net::NetError::ERR_NET_PORT_INVALID);
				}
				auto port = static_cast<int>(port_num);
				return connect(hostname, port);
			}

			void disconnect()
			{
				_status =
				    TcpTlsSession::TcpSessionStatus::SESSION_SHUTING_DOWN_SSH;
				_read_buffer.clear();
				_write_queue.clear();
				do_disconnect();
			}

			TcpTlsSession::TcpSessionStatus getStatus() const
			{
				return _status;
			}

			template <typename T>
			std::string send(const T &data)
			    requires net::BufferContainer<T>
			{
				try_send_all_buffer();
				auto snd_id = encrypt::generate_random_sha256_string(64);

				if (!_write_queue.empty())
				{
					write_node n;
					n._data.resize(data.size());
					std::memcpy(n._data.data(), data.data(), data.size());
					n._write_id = snd_id;
					_write_queue.push_back(n);
				}
				else
				{
					std::size_t offer_set = 0;
					do_send(data, snd_id, offer_set);
					if (offer_set != data.size())
					{
						write_node n;
						n._data.resize(data.size());
						std::memcpy(n._data.data(), data.data(), data.size());
						n._write_id = snd_id;
						n._offer_set = offer_set;
						_write_queue.push_back(n);
					}
				}
				return snd_id;
			}

			std::string send(const char *str)
			{
				std::span<const char> data(str, std::strlen(str));
				return send(data);
			}

		private:
			OnConnectedCallBack _on_connected;
			OnDisConnectedCallBack _on_disconnected;
			OnSendCallBack _on_sent;
			OnDataCallBack _on_data;
			OnErrorCallBack _on_error;
			SSL_CTX *_ctx;
			SSL *_ssl;
			std::vector<char> _read_buffer;
			std::deque<write_node> _write_queue;
			std::string _hostname;
			TcpSessionStatus _status;
			int _port;
			int _socket_fd;
			bool _auto_connect;

			bool is_fatal_error(int ssl_err)
			{
				return !(ssl_err == SSL_ERROR_WANT_READ ||
				         ssl_err == SSL_ERROR_WANT_WRITE);
			}

			void do_connect_socket()
			{
				struct addrinfo hints = {}, *res = nullptr;
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				int err =
				    ::getaddrinfo(_hostname.c_str(),
				                  std::to_string(_port).c_str(), &hints, &res);
				if (err != 0 || !res)
				{
					_on_error(static_cast<net::NetError>(err));
					disconnect();
					return;
				}
				_socket_fd = ::socket(res->ai_family, res->ai_socktype,
				                      res->ai_protocol);
				if (_socket_fd < 0)
				{
					freeaddrinfo(res);
					_on_error(static_cast<net::NetError>(errno));
					disconnect();
					return;
				}
				auto nonblock_ret = set_nonblocking(errno);
				if (0 > nonblock_ret)
				{
					_on_error(static_cast<net::NetError>(errno));
					disconnect();
					return;
				}
				auto connect_ret =
				    ::connect(_socket_fd, res->ai_addr, res->ai_addrlen);
				freeaddrinfo(res);
				if (0 > connect_ret)
				{
					if (EINPROGRESS != errno)
					{
						_on_error(static_cast<net::NetError>(errno));
						disconnect();
						return;
					}
					else
					{
						_status = TcpTlsSession::TcpSessionStatus::
						    SESSION_SOCKET_CONNECTING;
						return;
					}
				}
				else
					_status =
					    TcpTlsSession::TcpSessionStatus::SESSION_TSL_CONNECTING;
			}

			void do_check_socket_connecting()
			{
				int err = 0;
				socklen_t len = sizeof(err);
				if (getsockopt(_socket_fd, SOL_SOCKET, SO_ERROR, &err, &len) <
				    0)
				{
					_on_error(static_cast<net::NetError>(errno));
					disconnect();
					return;
				}
				if (err == 0)
				{
					_status =
					    TcpTlsSession::TcpSessionStatus::SESSION_TSL_CONNECTING;
					do_tls_connect();
					return;
				}
				else if (err == EINPROGRESS || err == EALREADY)
					return;
				_on_error(static_cast<net::NetError>(errno));
				disconnect();
			}

			void do_check_tls_connecting()
			{
				int ret = SSL_connect(_ssl);
				if (ret <= 0)
				{
					if (is_fatal_error(ret))
					{
						auto err = SSL_get_error(_ssl, ret);
						_on_error(static_cast<net::NetError>(err));
						disconnect();
					}
					return;
				}
				_status = TcpTlsSession::TcpSessionStatus::SESSION_CONNECTED;
				_on_connected();
			}
			void do_tls_connect()
			{
				_ssl = SSL_new(_ctx);
				if (!_ssl)
				{
					auto err = ERR_get_error();
					_on_error(static_cast<net::NetError>(err));
					disconnect();
					return;
				}
				if (!SSL_set_fd(_ssl, _socket_fd))
				{
					auto err = ERR_get_error();
					_on_error(static_cast<net::NetError>(err));
					disconnect();
					return;
				}
				if (!SSL_set_tlsext_host_name(_ssl, _hostname.c_str()))
				{
					auto err = ERR_get_error();
					_on_error(static_cast<net::NetError>(err));
					disconnect();
					return;
				}
				do_check_tls_connecting();
			}

			void do_connect()
			{
				do_connect_socket();
				if (_status ==
				    TcpTlsSession::TcpSessionStatus::SESSION_TSL_CONNECTING)
					do_tls_connect();
			}

			template <typename T>
			void do_send(const T &data, const std::string &write_id,
			             std::size_t &offer_set)
			    requires net::BufferContainer<T>
			{
				const static auto max_int = std::numeric_limits<int>::max();
				auto ptr = data.data() + offer_set;
				auto rest_len = data.size() - offer_set;
				auto snd_size = static_cast<int>(rest_len % max_int);
				int ret =
				    SSL_write(_ssl, static_cast<const void *>(ptr), snd_size);
				if (ret <= 0)
				{
					int err = SSL_get_error(_ssl, ret);
					if (is_fatal_error(err))
					{
						_on_error(static_cast<net::NetError>(err));
						disconnect();
					}
					return;
				}
				offer_set += ret;
				if (offer_set == data.size())
					_on_sent(write_id);
			}
			void try_send_all_buffer()
			{
				while (!_write_queue.empty())
				{
					auto &node = _write_queue.front();
					do_send(node._data, node._write_id, node._offer_set);
					if (node._offer_set != node._data.size())
						return;
					else
						_write_queue.pop_front();
				}
			}

			void do_read()
			{
				auto try_read_size = static_cast<int>(_read_buffer.size());
				auto ret = SSL_read(_ssl, _read_buffer.data(), try_read_size);
				if (ret <= 0)
				{
					int err = SSL_get_error(_ssl, ret);
					if (is_fatal_error(err))
					{
						_on_error(static_cast<net::NetError>(err));
						disconnect();
					}
					return;
				}
				auto read_size = static_cast<std::size_t>(ret);
				_on_data(std::span<const char>(_read_buffer.data(), read_size));
			}

			void do_disconnect()
			{
				if (_ssl)
				{
					auto shutdown_rt = SSL_shutdown(_ssl);
					if (shutdown_rt < 0)
					{
						auto ssl_err = SSL_get_error(_ssl, shutdown_rt);
						if (!is_fatal_error(ssl_err))
							return;
						else
							_on_error(static_cast<net::NetError>(ssl_err));
					}
					SSL_free(_ssl);
					_ssl = nullptr;
				}
				if (_socket_fd >= 0)
				{
					::close(_socket_fd);
					_socket_fd = -1;
				}
				_on_disconnected();
				if (_auto_connect)
					_status =
					    TcpTlsSession::TcpSessionStatus::SESSION_DISCONNECTED;
				else
					_status = TcpTlsSession::TcpSessionStatus::SESSION_IDLE;
			}
		};
		const encrypt::OpenSSLInitializer TcpTlsSession::_ssl_initialize;
	} // namespace tcp
} // namespace net

#endif // NET_TCP_TCP_TLS_SESSION_H

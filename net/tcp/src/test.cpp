#include <iostream>
#include <net/error.hpp>
#include <net/tcp/TcpTlsSession.hpp>

using namespace net::tcp;
int main(int, const char **)
{
	const char *request = "GET /ws HTTP/1.1\r\n"
	                      "Host: api.hyperliquid.xyz\r\n"
	                      "Upgrade: websocket\r\n"
	                      "Connection: Upgrade\r\n"
	                      "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
	                      "Sec-WebSocket-Version: 13\r\n"
	                      "\r\n";
	TcpTlsSession client([&]() { client.send(request); }, []() {},
	                     [](const std::string &) {},
	                     [](const std::span<const char> &data)
	                     {
		                     std::vector<char> msg;
		                     msg.resize(data.size() + 1);
		                     std::memcpy(msg.data(), data.data(), data.size());
		                     msg[data.size()] = '\0';
		                     std::cout << msg.data() << std::endl;
	                     });
	client.connect("api.hyperliquid.xyz:443");
	while (true)
		client.poll();
	return 0;
}

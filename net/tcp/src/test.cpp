#include <net/error.hpp>
#include <net/tcp/TcpTlsSession.hpp>

using namespace net::tcp;
int main(int, const char **)
{
	TcpTlsSession client;
	auto ret = client.connect("api.hyperliquid.xyz:443");
	if (ret != net::NetError::ERR_OK)
	{
		// handle error
		return 1;
	}
	const char *request = "GET /ws HTTP/1.1\r\n"
	                      "Host: api.hyperliquid.xyz\r\n"
	                      "Upgrade: websocket\r\n"
	                      "Connection: Upgrade\r\n"
	                      "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
	                      "Sec-WebSocket-Version: 13\r\n"
	                      "\r\n";
	auto sent_rt = client.send(request);
	if (net::NetError::ERR_OK != sent_rt)
	{
	}

	char buffer[4096];
	ssize_t received;
	while ((received = client.recv(buffer, sizeof(buffer) - 1)) > 0)
	{
		buffer[received] = 0;
		printf("%s", buffer);
	}

	client.disconnect();

	return 0;
}

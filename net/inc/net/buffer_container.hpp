#ifndef NET_BUFFER_COINTER_H
#define NET_BUFFER_COINTER_H
#include <concepts>
#include <span>
#include <vector>

namespace net
{
	template <typename T>
	concept BufferContainer = std::same_as<T, std::span<const char>> ||
	                          std::same_as<T, std::vector<char>>;
}
#endif // NET_BUFFER_COINTER_H

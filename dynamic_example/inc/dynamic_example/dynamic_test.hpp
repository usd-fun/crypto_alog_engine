#ifndef __MAKE_TEST_DYNAMIC_TEST__
#define __MAKE_TEST_DYNAMIC_TEST__
#include <static_example/static_test.hpp>
namespace make_test
{
	class dynamic_test : public static_test
	{
	public:
		dynamic_test() = default;
		virtual ~dynamic_test() = default;
	public:
		virtual void print();
	};
}
#endif //__MAKE_TEST_DYNAMIC_TEST__

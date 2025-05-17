#ifndef __MAKE_TEST_STATIC_TEST__
#define __MAKE_TEST_STATIC_TEST__
namespace make_test
{
	class static_test
	{
	public:
		static_test() = default;
		virtual ~static_test() = default;
	public:
		virtual void print();
	};
}
#endif //__MAKE_TEST_STATIC_TEST__

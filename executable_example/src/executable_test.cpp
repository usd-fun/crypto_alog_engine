#include <dynamic_example/dynamic_test.hpp>
#include <iostream>
using namespace make_test;

int main(void)
{
	static_test st;
	dynamic_test dt;
	st.print();
	dt.print();
	return 0;
}

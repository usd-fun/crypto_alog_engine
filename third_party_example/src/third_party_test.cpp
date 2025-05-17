#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>

class py_test
{
public:
	int add(int x, int y)
	{
		return x + y;
	}
};


PYBIND11_MODULE(TARGET_NAME, m)
{
	pybind11::class_<py_test>(m, "py_test")
		.def(pybind11::init<>())
		.def("add", &py_test::add);
}

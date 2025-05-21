#include <iostream>

__attribute__((constructor)) void init()
{
    std::cout << "[mylib] Constructor called! Injected dylib running.\n";
}

extern "C" void hello()
{
    std::cout << "[mylib] mylib_entry() called manually.\n";
}

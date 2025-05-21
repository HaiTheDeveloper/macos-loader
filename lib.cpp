#include <iostream>

__attribute__((constructor)) void init()
{
    volatile int x = 42;
    (void)x;

    std::cout << "[mylib] Constructor called! Injected dylib running.\n";
}

extern "C" void hello()
{
    volatile int x = 42;
    (void)x;

    std::cout << "[mylib] mylib_entry() called manually.\n";
}

#include <iostream>

__attribute__((constructor)) int init()
{
    return 21;
}

extern "C" int hello()
{
    return 42;
}

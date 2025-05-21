// test.cpp
#include <dlfcn.h>
#include <iostream>

int main()
{
    void *handle = dlopen("./lib.dylib", RTLD_LAZY);
    if (!handle)
    {
        std::cerr << "Failed to load dylib\n";
        return 1;
    }

    using FuncType = void (*)();
    FuncType func = (FuncType)dlsym(handle, "hello");
    if (func)
    {
        func();
    }
    else
    {
        std::cerr << "Symbol not found\n";
    }

    dlclose(handle);
    return 0;
}

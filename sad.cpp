#include <sys/mman.h>
#include <iostream>
int main()
{
    void *mem = mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }
    std::cout << "mmap succeeded\n";
    munmap(mem, 4096);
    return 0;
}
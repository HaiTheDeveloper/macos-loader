#include <stdio.h>

__attribute__((constructor)) void init()
{
    printf("called ctor\n");
}

void _hello()
{
    printf("called hello\n");
}

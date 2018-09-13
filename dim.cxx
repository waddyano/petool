#include <windows.h>
#include <stdio.h>

void a()
{
    printf("a!\n");
}

void b()
{
    printf("b %d\n", 42);
}

void main()
{
    a();
    b();
}

static void write_console(const char *msg)
{
    DWORD nWritten;

    const char *p = msg;
    while (*p != '\0')
        ++p;
    DWORD len = (DWORD)(p - msg);
    AllocConsole();
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), msg, len, &nWritten, nullptr);
}

extern "C" int mainCRTStartup();

extern "C" void myStartup()
{
    write_console("myStartup\n");
    mainCRTStartup();
}

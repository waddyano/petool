#include <windows.h>

extern void __declspec(dllimport) dlla();

extern void __declspec(dllimport) dllb(int a);

extern void __declspec(dllimport) dllc(double a);

void a()
{
    dlla();
}

void b()
{
    dllb(42);
    dllc(4.2);
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

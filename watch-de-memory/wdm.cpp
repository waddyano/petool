#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Windows.h>
#if 0
#ifndef _DEBUG
extern "C" BOOL WINAPI _DllMainCRTStartup (HINSTANCE hinstDLL, DWORD fdwReason,
                                         LPVOID lpvReserved)
#else
BOOL WINAPI DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
#endif
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hinstDLL);

    return TRUE;
    UNREFERENCED_PARAMETER (lpvReserved);
}
#endif

static void write_console(const char *fmt, ...)
{
    DWORD nWritten;
    char buf[1024];
    
    va_list ap;
    va_start(ap, fmt);
    size_t len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    AllocConsole();
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)len, &nWritten, nullptr);
}

extern "C" __declspec(dllexport) void * wdm_malloc(size_t sz)
{
    void *res = malloc(sz);
    write_console("malloc %zd => %p\n", sz, res);
    return res;
}

extern "C" __declspec(dllexport) void wdm_free(void *p)
{
    write_console("free %p\n", p);
    free(p);
}

extern "C" __declspec(dllexport) void *wdm_realloc(void *p, size_t sz)
{
    void *res = realloc(p, sz);
    write_console("realloc %p %zd => %p\n", p, sz, res);
    return res;
}

extern "C" __declspec(dllexport) LPVOID wdm_HeapAlloc(HANDLE heap, DWORD flags, SIZE_T sz)
{
    LPVOID res = HeapAlloc(heap, flags, sz);
    write_console("HeapAlloc %p %zd => res\n", heap, sz, res);
    return res;
}

extern "C" __declspec(dllexport) BOOL wdm_HeapFree(HANDLE heap, DWORD flags, LPVOID p)
{
    write_console("HeapFree %p %p\n", heap, p);
    return HeapFree(heap, flags, p);
}

extern "C" __declspec(dllexport) LPVOID wdm_HeapReAlloc(HANDLE heap, DWORD flags, LPVOID p, SIZE_T sz)
{
    LPVOID res = HeapReAlloc(heap, flags, p, sz);
    write_console("HeapReAlloc %p %zd => %p\n", p, sz, res);
    return res;
}

extern "C" __declspec(dllexport) SIZE_T wdm_HeapSize(HANDLE heap, DWORD flags, LPVOID p)
{
    SIZE_T res = HeapSize(heap, flags, p);
    write_console("HeapSize %p %p => %zd\n", heap, p, res);
    return res;
}


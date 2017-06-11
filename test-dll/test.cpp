#include <excpt.h>
#include <math.h>
#include <intrin.h>
#include <stdio.h>
#include <string>
#include <Windows.h>

#include "test.h"

static double a[10];
static long flags[99];

static char *strings []
{
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twleve",
    "thirteen",
    "fourteen"
};

extern void dllfn1()
{
    for (int i = 0; i < 10; ++i)
        a[i] = sqrt(double(i));

    _InterlockedCompareExchange((volatile long *)&flags[50], 0, 1);
}

extern void dllfn2(int i, int j)
{
    switch (i)
    {
    case 0: printf("%s\n", strings[0]); break;
    case 1: printf("%s\n", strings[1]); break;
    case 2: printf("%s\n", strings[2]); break;
    case 3: printf("%s\n", strings[3]); break;
    case 4: printf("%s\n", strings[4]); break;
    case 5: printf("%s\n", strings[5]); break;
    case 6: printf("%s\n", strings[6]); break;
    case 7: printf("%s\n", strings[7]); break;
    case 8:
        switch (j)
        {
        case 100: printf("%s\n", strings[j-100]); break;
        case 101: printf("%s\n", strings[j-100]); break;
        case 102: printf("%s\n", strings[j-100]); break;
        case 103: printf("%s\n", strings[j-100]); break;
        case 104: printf("%s\n", strings[j-100]); break;
        case 105: printf("%s\n", strings[j-100]); break;
        case 106: printf("%s\n", strings[j-100]); break;
        case 107: printf("%s\n", strings[j-100]); break;
        case 108: printf("%s\n", strings[j-100]); break;
        }
    default:
        printf("default\n");
        break;
    }
    switch (j)
    {
    case 100: printf("a %s\n", strings[j-100]); break;
    case 101: printf("b %s\n", strings[j-101]); break;
    case 102: printf("c %s\n", strings[j-102]); break;
    case 103: printf("d %s\n", strings[j-103]); break;
    case 104: printf("e %s\n", strings[j-104]); break;
    case 105: printf("f %s\n", strings[j-105]); break;
    case 106: printf("g %s\n", strings[j-106]); break;
    case 107: printf("h %s\n", strings[j-107]); break;
    case 108: printf("i %s\n", strings[j-108]); break;
    case 118: printf("i %s\n", strings[j-118]); break;
    }
}

static void t()
{
    throw std::string("boom");
}

static bool vio()
{
    __try
    {
        int *x = 0;
        printf("about to blow!\n");
        *x = 99;
        return false;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        printf("vio! %d\n", 0x1234);
        return true;
    }
}

static bool afn(bool seh)
{
    std::string s("local");
    if (seh)
        return vio();
    else
        t();
}

static bool b(bool seh)
{
    std::string s("local");
    try
    {
        return afn(seh);
    }
    catch (const std::string &e)
    {
        printf("caught %s\n", e.c_str());
        return true;
    }
    catch (...)
    {
        return false;
    }
}

extern bool excpt(bool seh)
{
    std::string s("mainlocal");
    return b(seh);
}

extern void crit()
{
    CRITICAL_SECTION sect;
    InitializeCriticalSectionAndSpinCount(&sect, 4000);
    EnterCriticalSection(&sect);
    LeaveCriticalSection(&sect);
    DeleteCriticalSection(&sect);
}

extern int dllfn3(char c)
{
    int x = 4;
    int z = c + 1;
    int zz = c + 2;
    int zzz = c + 3;
    if (z != 0)
    { 
        --z;
        if (zz != 0)
            --zzz;
    }
    switch (z)
    {
    case '0':
    case 'a':
        x += c;
    case '1':
    case 'b':
        x += c;
    case '2':
    case 'c':
        x += c;
    case '3':
    case 'd':
        x += c;
    case '4':
    case 'e':
        x += c;
    case '5':
    case 'f':
        x += c;
    case '6':
    case 'g':
        x += c;
    case '7':
    case 'h':
        x += c;
    case '8':
    case 'i':
        x += c;
    case '9':
    case 'j':
        x += c;
        break;
    case 10001:
        x -= 99;
        break;
    case 10003:
        x -= 999;
        break;
    case 10005:
        x -= 9999;
        break;
    case 10007:
        x -= 99999;
        break;
    case 10009:
        x -= 999999;
        break;
    case 10010:
        x -= 999999;
        break;
    case 10011:
        x -= 999998;
        break;
    case 10013:
        x -= 999997;
        break;
    }
    printf("%d %d %d\n", z, zz, zzz);
    return x * 3;
}

class E1 : public std::exception
{
public:
    const char *what() const
    {
        return "E1";
    }
};

class E2 : public E1
{
public:
    const char *what() const
    {
        return "E2";
    }
};

static void throw1(int i)
{
    switch (i)
    {
    case 1:
        throw E1();
    case 2:
        throw E2();
    case 3:
        throw std::string("xyzzy");
    case 4:
        throw 99;
    }
}

extern void excpt2(int i) 
{
    try
    {
        throw1(i);
    }
    catch (const E1 &e)
    {
        printf("caught %s\n", e.what());
    }
    catch (const std::string &s)
    {
        printf("caught another %s\n", s.c_str());
    }
    catch (...)
    {
        printf("caught the dregs!\n");
    }
}
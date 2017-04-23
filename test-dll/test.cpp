#include <math.h>
#include <intrin.h>
#include <stdio.h>

#define EXPORT __declspec(dllexport)

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

extern "C" EXPORT void dllfn1()
{
    for (int i = 0; i < 10; ++i)
        a[i] = sqrt(double(i));

    _InterlockedCompareExchange((volatile long *)&flags[50], 0, 1);
}

extern "C" EXPORT void dllfn2(int i, int j)
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

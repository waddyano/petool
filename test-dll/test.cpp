#include <math.h>
#include <intrin.h>

#define EXPORT __declspec(dllexport)

static double a[10];
static long flags[99];

extern "C" EXPORT void dllfn1()
{
    for (int i = 0; i < 10; ++i)
        a[i] = sqrt(double(i));

    _InterlockedCompareExchange((volatile long *)&flags[50], 0, 1);
}

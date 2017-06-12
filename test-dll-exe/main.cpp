#include <stdio.h>
#include "test.h"

int main()
{
    printf("%d\n", dllfn3('a'));
    printf("excpt seh %d\n", excpt(true));
    printf("excpt c++ %d\n", excpt(false));
    excpt2(1);
    excpt2(2);
    excpt2(3);
    excpt2(4);
    return 0;
}
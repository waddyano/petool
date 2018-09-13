#include <stdio.h>
#include <stdlib.h>

int  main()
{
    int *ar = (int *)malloc(10 * sizeof(int));

    for (int i = 0; i < 9; ++i)
        ar[i] = i;

    for (int i = 0; i < 10; ++i)
        ar[i] += i;

    for (int i = 0; i < 10; ++i)
        printf("%d\n", ar[i]);
    free(ar);
    printf("%d\n", ar[0]);
    return 0;
}
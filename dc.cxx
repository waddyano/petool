#include <stdio.h>
#include <typeinfo>
#include <vector>

static int iarray[] = { 1, 2, 3 };

struct S
{
    int *i;
    const char *s;
};

static const S  s = { iarray, "a string" };

class A
{
public:
    virtual void m() { printf("A::m\n"); }
};

class __declspec(dllexport) B : public A
{
public:
    virtual void m() { printf("B::m\n"); }
};

template <class T>
class V
{
public:
    virtual void fn();
    T m;
};

class __declspec(dllexport) C : public V<int>
{
public:
    virtual void m() { printf("B::m\n"); }
};

static void u(A *a)
{
    printf("a %s\n", typeid(*a).name());
    B * b = dynamic_cast<B *>(a);
    printf("b %p\n", b);
}

static void uv(V<int> *a)
{
    printf("a %s\n", typeid(*a).name());
    auto b = dynamic_cast<C *>(a);
    printf("b %p\n", b);
}


static void v(void *x)
{
    u((A *)x);
}

extern "C" char __ImageBase;

static unsigned long imageOffset(void *p)
{
    return (char *)p - &__ImageBase;
}

struct RTTIObjectLocator
{
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int typeDescriptorOffset;
    unsigned int classHierarchyDescriptorOffset;
    unsigned int selfOffset; //??
};

struct RTTIClassHierarchyDescriptor
{
    unsigned int a;
    unsigned int b;
    unsigned int arrayLength;
    unsigned int baseClassArrayOffset;
};

struct RTTIBaseClassDescriptor
{
    unsigned int typeDescriptorOffset;
    unsigned int b;
    unsigned int c;
    unsigned int d;
    unsigned int e;
    unsigned int f;
    unsigned int classHierarchyDescriptorOffset;
};

struct RTTITypeDescriptor
{
    void *typeInfoVTable;
    void *cache;
    char name[1];
};

#if 0
extern "C" void *__RTtypeid(void*);

int main()
{
    printf("s %s %d\n", s.s, s.i[0]);
    B b;
    void *rtti = __RTtypeid(&b);
    void *vt = * (void **) &b;
    printf("base %p\n", &__ImageBase);
    printf("vt %p\n", vt);
    void *rt = ((void **)vt)[-1];
    printf("rt %p %lx\n", rt, imageOffset(rt));
    RTTIObjectLocator *ol = (RTTIObjectLocator *)rt;
    printf("tdo %lx\n", ol->typeDescriptorOffset);
    printf("chd %lx\n", ol->classHierarchyDescriptorOffset);
    printf("self %lx\n", ol->selfOffset);
    RTTITypeDescriptor *rtd = (RTTITypeDescriptor *)(&__ImageBase + ol->typeDescriptorOffset);
    printf("%s\n", rtd->name);
    RTTIClassHierarchyDescriptor *chd = (RTTIClassHierarchyDescriptor *)(&__ImageBase + ol->classHierarchyDescriptorOffset);
    printf("base class %lx - len %ld\n", chd->baseClassArrayOffset, chd->arrayLength);
    unsigned int *ar = (unsigned int *)(&__ImageBase + chd->baseClassArrayOffset);
    for (unsigned int i = 0; i < chd->arrayLength; ++i )
    { 
        printf("%lx\n", ar[i]);
        RTTIBaseClassDescriptor *bcd = (RTTIBaseClassDescriptor *)(&__ImageBase + ar[i]);
        printf("tdo %lx chd %d\n", bcd->typeDescriptorOffset, bcd->classHierarchyDescriptorOffset);
    }


    void *rtti2 = &__ImageBase + ol->typeDescriptorOffset;
    printf("rtti2 %p\n", rtti2);
    printf("rtti %p %lx\n", rtti, imageOffset(rtti));
    printf("*rtti %p\n", * (void **)rtti);

    printf("b is at %p\n", &b);
    v(&b);
    B *x = new B();
    int *ix = new int[10];
    ix[11] = 99;
    printf("x is at %p\n", x);
    v(x);
    return 0;
}
#endif
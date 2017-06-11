#pragma once

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


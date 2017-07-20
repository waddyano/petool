#pragma once

struct ThrowInfo
{
    unsigned int a;
    unsigned int destructorOffset;
    unsigned int b;
    unsigned int catchableTypeArrayOffset;
};

struct CatchableTypeArray
{
    unsigned int count;
    unsigned int catchableTypeOffsets[1];
};

struct CatchableType
{
    unsigned int a;
    unsigned int typeDescriptorOffset;
    unsigned int c;
    unsigned int d;
    unsigned int dummy;
    unsigned int e;
    unsigned int copyConstructorOffset;
};

struct XData
{
    unsigned int magic;
    unsigned int b;
    unsigned int unwindMapOffset;
    unsigned int d;
    unsigned int tryMapOffset;
    unsigned int stateCount;
    unsigned int stateOffset;
    unsigned int h;
    unsigned int i;
    unsigned int EHFlags;
};

struct IP2Offset
{
    unsigned int functionOffset;
    unsigned int b;
};

struct UnwindMap
{
    unsigned int a;
    unsigned int destructorOffset;
    unsigned int c;
    unsigned int d;
    unsigned int e;
    unsigned int f;
};

struct TryMap
{
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int handlerMapCount;
    unsigned int handlerMapOffset;
};

struct HandlerMap
{
    unsigned int a;
    unsigned int typeDescriptorOffset;
    unsigned int c;
    unsigned int catchFunctionOffset;
    unsigned int e;
};
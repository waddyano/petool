#pragma once
#include <distorm.h>
#include "Rva.h"

struct BasicBlock
{
    static int nextId;

    BasicBlock(Rva s, unsigned long l) : id(++nextId), start(s), length(l), nSuccessors(0)
    {
    }
    BasicBlock(Rva s) : id(0), start(s), length(0), nSuccessors(0)
    {
    }
    BasicBlock() : id(0), start(), length(0), nSuccessors(0)
    {
    }
    BasicBlock(const BasicBlock &other) : 
        id(++nextId), start(other.start), length(other.length), nSuccessors(other.nSuccessors), baseReg(other.baseReg), baseRegSet(other.baseRegSet), baseRegClobbered(other.baseRegClobbered)
    {
        for (int i = 0; i < nSuccessors; ++i)
            successors[i] = other.successors[i];
    }
    unsigned int id;
    Rva start;
    unsigned long length;
    int nSuccessors;
    Rva successors[2];
    int baseReg = R_NONE;
    unsigned long baseRegSet = 0;
    unsigned long baseRegClobbered = 0;
};

struct BlockStartLess
{
    bool operator() (const BasicBlock *a, const BasicBlock *b) const
    {
        return a->start < b->start;
    }
};


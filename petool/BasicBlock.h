#pragma once
#include <distorm.h>
#include <string>
#include <vector>
#include "Rva.h"

struct BasicBlock
{
    static int nextId;

    BasicBlock(Rva s, unsigned long l) : id(++nextId), start(s), length(l)
    {
    }

    BasicBlock(Rva s) : id(0), start(s), length(0)
    {
    }

    BasicBlock() : id(0), start(), length(0)
    {
    }

    BasicBlock(const BasicBlock &other) : 
        id(++nextId), start(other.start), length(other.length), successors(other.successors), predecessors(other.predecessors), 
        baseReg(other.baseReg), baseRegSet(other.baseRegSet), baseRegClobbered(other.baseRegClobbered),
        endsInIndirectJump(other.endsInIndirectJump), propagated(other.propagated), isJumpTable(other.isJumpTable), isFunctionStart(other.isFunctionStart), containsCall(other.containsCall),
        jumpTableSize(other.jumpTableSize), jumpTableReg(other.jumpTableReg)
    {
    }

    std::string GetLabel() const
    {
        if (!label.empty())
            return label;
        char buf[64];
        snprintf(buf, sizeof(buf), "%s_bb%u", isFunctionStart ? "fn" : "lab", id);
        return buf;
    }

    unsigned int id;
    std::string label;
    Rva start;
    unsigned long length;
    std::vector<Rva> successors;
    std::vector<Rva> predecessors;
    int baseReg = R_NONE;
    unsigned long baseRegSet = 0;
    unsigned long baseRegClobbered = 0;
    bool endsInIndirectJump = false;
    bool propagated = false;
    bool isJumpTable = false;
    bool isFunctionStart = false;
    bool containsCall = false;
    unsigned long jumpTableSize = 0;
    unsigned long jumpTableElementSize = 0;
    int jumpTableReg = R_NONE;
};

struct BlockStartLess
{
    bool operator() (const BasicBlock *a, const BasicBlock *b) const
    {
        return a->start < b->start;
    }
};


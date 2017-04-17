#pragma once

#include <distorm.h>
#include <map>
#include <set>
#include <vector>
#include <windows.h>

#include "Rva.h"
#include "Target.h"

class BasicBlockAnalyzer
{
public:
    BasicBlockAnalyzer(const unsigned char * text, Rva textVa, DWORD textSize) : m_text(text), m_textVa(textVa), m_textSize(textSize)
    {
    }

    void Analyze(std::set<Rva> &&seedRvas);
    const std::set<BasicBlock *, BlockStartLess> &GetBasicBlocks() const
    {
        return m_basicBlocks;
    }
    const std::map<Rva, TargetInfo>  &GetTargets() const
    {
        return m_targets;
    }
private:
    bool GatherNewTargets(const _CodeInfo &ci, Rva va, const _DInst dinst);
    bool CheckBaseRegLifetime(const _CodeInfo &ci, Rva va, const _DInst dinst);
    void PropagateBaseReg();
    void AddSuccessor(Rva next);
    bool InTextSegment(Rva rva) const
    {
        return rva >= m_textVa && rva < m_textVa + m_textSize;
    }
    void SplitBasicBlock(BasicBlock *bb, unsigned long splitOffset);
    const unsigned char *m_text;
    Rva m_textVa;
    DWORD m_textSize;
    std::set<BasicBlock *, BlockStartLess> m_basicBlocks;
    std::map<Rva, TargetInfo> m_targets;
	std::set<Rva> m_newTargets;
    std::set<Rva> m_unprocessedTargets;
    BasicBlock m_newBlock;
    DWORD m_splitAt;
};

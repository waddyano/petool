#define _CRT_SECURE_NO_WARNINGS
#include <mnemonics.h>
#include <unordered_set>
#include <vector>

#include "BasicBlock.h"
#include "BasicBlockAnalyzer.h"
#include "Disassemble.h"

void BasicBlockAnalyzer::AddSuccessor(Rva r)
{
    m_newBlock.successors.push_back(r);
}

static void SimplePrint(const _CodeInfo &ci, Rva va, const _DInst dinst)
{
	_DecodedInst decoded;
	distorm_format(&ci, &dinst, &decoded);
	_strlwr(reinterpret_cast<char *>(decoded.instructionHex.p));
	_strlwr(reinterpret_cast<char *>(decoded.mnemonic.p));
	if (decoded.operands.length > 0)
		_strlwr(reinterpret_cast<char *>(decoded.operands.p));
	Rva a = va + decoded.offset;

	printf("%0*lx %-24s %s%s%s\n", 16, a.ToUL(),
		(char*)decoded.instructionHex.p, (char*)decoded.mnemonic.p,
		decoded.operands.length != 0 ? " " : "", (char*)decoded.operands.p);
}

void BasicBlockAnalyzer::AddTargetToProcess(Rva target, BasicBlock *predBB)
{
    auto it = m_unprocessedTargets.find(target);
    if (it != m_unprocessedTargets.end())
    {
        if (predBB != nullptr)
            it->second.push_back(predBB);
    }
    else
    {
        if (predBB != nullptr)
            m_unprocessedTargets.insert(std::make_pair(target, std::vector<BasicBlock*>(1,predBB)));
        else
            m_unprocessedTargets.insert(std::make_pair(target, std::vector<BasicBlock*>()));
    }
}

bool BasicBlockAnalyzer::CheckForJumpTable(BasicBlock *bb, const _CodeInfo &ci, Rva va, const _DInst dinst)
{
    printf("jump:\n");
    
    SimplePrint(ci, va, dinst);
	for (int j = 0; j < OPERANDS_NO; ++j)
	{
        bool addJumpTable = false;
        unsigned long sz;
        if (dinst.opcode == I_MOVZX && dinst.ops[j].type == O_MEM && (dinst.base == bb->baseReg || dinst.ops[j].index == bb->baseReg))
        {
            BasicBlock *prevBB = nullptr;
            BasicBlock t(bb->predecessors[0]);
            auto it = m_basicBlocks.find(&t);
            if (it != m_basicBlocks.end())
            { 
                sz = (*it)->jumpTableSize;
                printf("disp %lld size %d\n", dinst.disp, sz);
                unsigned long max_off = 0;
                for (unsigned long i = 0; i < sz; ++i)
                { 
                    unsigned long off;
                    
                    if (dinst.ops[j].size == 8)
                        off = ((unsigned char *)(m_text + (dinst.disp - m_textVa.ToUL())))[i];
                    else if (dinst.ops[j].size == 16)
                        off = ((unsigned short *)(m_text + (dinst.disp - m_textVa.ToUL())))[i];
                    else if (dinst.ops[j].size == 32)
                        off = ((unsigned long *)(m_text + (dinst.disp - m_textVa.ToUL())))[i];
                    if (off > max_off)
                        max_off = off;
                }
                printf("max off %lu\n", max_off);
                jumpTableSize = max_off + 1;
                addJumpTable = true;           
            }
        }
        if (dinst.opcode == I_MOV && dinst.ops[j].type == O_MEM && dinst.ops[j].size == 32 && dinst.base == bb->baseReg)
        {
            BasicBlock *prevBB = nullptr;
            BasicBlock t(bb->predecessors[0]);
            auto it = m_basicBlocks.find(&t);
            if (it != m_basicBlocks.end())
            { 
                sz = jumpTableSize > 0 ? jumpTableSize : (*it)->jumpTableSize;
                printf("disp %lld size %d\n", dinst.disp, sz);
                std::set<Rva> added;
                for (unsigned long i = 0; i < sz; ++i)
                { 
                    unsigned long off = ((unsigned long *)(m_text + (dinst.disp - m_textVa.ToUL())))[i];
                    printf("off %lx\n", off);
                    Rva next(off);
                    if (added.count(next) > 0)
                        continue;
                    added.insert(next);
                    AddTargetToProcess(next, bb);
                    bb->successors.push_back(next);
                }

                addJumpTable = true;
            }
        }

        if (addJumpTable)
        { 
            auto jt = new BasicBlock();
            jt->isJumpTable = true;
            jt->start = Rva(dinst.disp);
            jt->jumpTableElementSize = dinst.ops[j].size / 8;
            jt->length = sz * jt->jumpTableElementSize;
            m_basicBlocks.insert(jt);
        }
    }

    return true;
}

static int clobberedReg(int reg)
{
    if (reg >= R_EAX && reg <= R_R15D)
        return reg - R_EAX + R_RAX;
    return reg;
}

bool BasicBlockAnalyzer::CheckBaseRegLifetime(BasicBlock *bb, const _CodeInfo &ci, Rva va, const _DInst dinst)
{
    if ((dinst.flags & FLAG_DST_WR) != 0 && dinst.ops[0].type == O_REG && clobberedReg(dinst.ops[0].index) == m_newBlock.baseReg)
    { 
    	Rva a = va + dinst.addr;

        printf("Lifetime Clobber! %lx - %d\n", bb->start.ToUL(), bb->baseRegSet);
        if (a == bb->start)
            bb->baseReg = R_NONE;
        else
            bb->baseRegClobbered = a - bb->start;
        return false;
    }

    return true;
}

void BasicBlockAnalyzer::CheckForJumpTableLimitCheck(const _CodeInfo &ci, Rva va, const _DInst dinst)
{
	Rva a = va + dinst.addr;

    if (m_jumpTableState == -1)
    { 
        if (dinst.opcode == I_CMP && dinst.ops[0].type == O_REG && dinst.ops[1].type == O_IMM)
        {
            m_newBlock.jumpTableReg = dinst.ops[0].index;
            if (dinst.ops[1].size == 8)
                m_newBlock.jumpTableSize = dinst.imm.byte;
            else if (dinst.ops[1].size == 32)
                m_newBlock.jumpTableSize = dinst.imm.dword;
            printf("%lx: reg size %d op size %d - compare against %d\n", a.ToUL(), dinst.ops[0].size, dinst.ops[1].size, m_newBlock.jumpTableSize);
            m_jumpTableState = 0;
        }
    }
    else if (m_jumpTableState == 0)
    {
        if (dinst.opcode == I_JA)
        {
            ++m_newBlock.jumpTableSize;
            printf("jump table? %lx - %d\n", a.ToUL(), m_newBlock.jumpTableSize);
            m_jumpTableState = 1;
        }
        else
        {
            m_newBlock.jumpTableSize = 0;
            m_jumpTableState = -1;
        }
    }
}

bool BasicBlockAnalyzer::GatherNewTargets(const _CodeInfo &ci, Rva va, const _DInst dinst)
{
	Rva a = va + dinst.addr;

    if ((dinst.flags & FLAG_DST_WR) != 0 && dinst.ops[0].type == O_REG && dinst.ops[0].index == m_newBlock.baseReg && m_newBlock.baseRegClobbered == 0)
    { 
        printf("Clobber! %lx - %d at %lx\n", m_newBlock.start.ToUL(), m_newBlock.baseRegSet, a.ToUL());
        if (a == m_newBlock.start)
        {
            m_newBlock.baseReg = R_NONE;
        }
        else
        { 
            m_newBlock.baseRegClobbered = a - m_newBlock.start;
        }
    }

    m_newBlock.length += dinst.size;

    unsigned int mfc = META_GET_FC(dinst.meta);

    if (dinst.opcode == I_LEA && (dinst.flags & FLAG_RIP_RELATIVE) != 0 && dinst.ops[1].type == O_SMEM)
    {
		Rva ea = va + INSTRUCTION_GET_RIP_TARGET(&dinst);
        if (m_interestingAddresses.count(ea) > 0 && m_interestingAddresses.count(ea - 8) > 0)
        { 
            m_possibleVTables.insert(ea);
        }
    }

	for (int j = 0; j < OPERANDS_NO; ++j)
	{
		if (dinst.ops[j].type == O_NONE)
			break;
		Rva target = Rva::Invalid();
		TargetType type = dinst.opcode == I_CALL ? TargetType::CFUNCTION : TargetType::LABEL;

		if (dinst.ops[j].type == O_PC)
		{
			target = va + INSTRUCTION_GET_TARGET(&dinst);
            if (target < a && target > m_newBlock.start)
            { 
                m_splitAt = target - m_newBlock.start;
                //printf("Backward loop! %lx start %lx - split at %ld\n", target.ToUL(), m_newBlock.start.ToUL(), m_splitAt);
            }
		}

		if (dinst.ops[j].type == O_SMEM && (dinst.flags & FLAG_RIP_RELATIVE) != 0)
		{
			target = va + INSTRUCTION_GET_RIP_TARGET(&dinst);
		}

        if (target != Rva::Invalid())
        { 
            if (dinst.opcode == I_LEA && (dinst.flags & FLAG_RIP_RELATIVE) != 0)
            {
                if (target.ToUL() == 0)
                {
                    m_newBlock.baseReg = dinst.ops[0].index;
                    m_newBlock.baseRegSet = a - m_newBlock.start;
                    m_newBlock.baseRegClobbered = 0;
                    printf("LEA @%lx %lx - %d - reg %s\n", a.ToUL(), m_newBlock.start.ToUL(), m_newBlock.baseRegSet, GET_REGISTER_NAME(m_newBlock.baseReg));
                }
            }

			auto it = m_targets.find(target);
			if (it == m_targets.end()) // && m_vaToImportedSymbols.count(target) == 0)
			{
                if (InTextSegment(target))
                    m_newTargets.insert(target);
                else
                    type = TargetType::DATA;

                m_targets.insert(std::make_pair(target, TargetInfo(type)));
			}
			else if (it != m_targets.end() && type == TargetType::CFUNCTION && it->second.targetType != TargetType::FUNCTION)
            { 
				it->second.targetType = type;
            }

            if (type == TargetType::CFUNCTION)
            {
                BasicBlock tmp(target);
                auto bb_it = m_basicBlocks.find(&tmp);
                if (bb_it != m_basicBlocks.end())
                    (*bb_it)->isFunctionStart = true;
            }

            if (mfc == FC_CND_BRANCH)
            { 
                AddSuccessor(target);
            }
        }
	}

    CheckForJumpTableLimitCheck(ci, va, dinst);

    Rva fallThruTarget = va + dinst.addr + dinst.size;
    if (mfc != FC_NONE && mfc != FC_UNC_BRANCH && mfc != FC_RET && mfc != FC_CALL && mfc != FC_INT)
    {
        m_targets.insert(std::make_pair(fallThruTarget, TargetInfo(TargetType::LABEL)));
        m_newTargets.insert(fallThruTarget);
        AddSuccessor(fallThruTarget);
    }

    bool cont = mfc == FC_NONE || mfc == FC_CALL;

    if (cont && (m_targets.count(a + dinst.size) > 0 || m_unprocessedTargets.count(a + dinst.size) > 0))
    { 
        AddSuccessor(fallThruTarget);
        cont = false;
    }

    if (dinst.opcode == I_JMP && dinst.ops[0].type == O_REG)
        m_newBlock.endsInIndirectJump = true;

    return cont;
}

void BasicBlockAnalyzer:: SplitBasicBlock(BasicBlock *bb, unsigned long splitOffset)
{
    Rva split = bb->start + splitOffset;
    BasicBlock *splitBB = new BasicBlock(split, bb->length - splitOffset);
    splitBB->successors = bb->successors;
    bb->successors.resize(1);
    bb->successors[0] = split;
    splitBB->predecessors.push_back(bb->start);
    m_basicBlocks.insert(splitBB);
    bb->length = splitOffset;
    if (bb->baseReg != R_NONE)
    {
        if (bb->baseRegSet >= splitOffset)
        {
            splitBB->baseReg = bb->baseReg;
            splitBB->baseRegSet = bb->baseRegSet - splitOffset;
            splitBB->baseRegClobbered = bb->baseRegClobbered - splitOffset;
            bb->baseReg = R_NONE;
        }
        else if (bb->baseRegClobbered >= splitOffset)
        {
            splitBB->baseReg = bb->baseReg;
            splitBB->baseRegSet = 0;
            splitBB->baseRegClobbered = bb->baseRegClobbered - splitOffset;
            bb->baseRegClobbered = bb->length;
        }
    }
}

static int getBaseReg(const std::vector<BasicBlock *> &bbs)
{
    int result = R_NONE;
    for (auto bb : bbs)
    {
        if (result == R_NONE)
            result = bb->baseReg;
        else if (result != bb->baseReg && bb->baseReg != R_NONE) // disagreement
            return R_NONE;
    }

    return result;
}

void BasicBlockAnalyzer::Analyze(std::set<Rva> &&seedRvas)
{
    for (auto rva : seedRvas)
        AddTargetToProcess(rva, nullptr);

    do
    { 
        while (!m_unprocessedTargets.empty())
        {
            Rva rva = m_unprocessedTargets.begin()->first;
            std::vector<BasicBlock *> predecessors = m_unprocessedTargets.begin()->second;

            m_unprocessedTargets.erase(rva);

            if (rva < m_textVa || rva >= m_textVa + m_textSize)
            {
                continue;
            }

            //printf("start at %lx\n", rva.ToUL());
            m_newTargets.clear();

            m_newBlock = BasicBlock(rva);
            for (auto pred : predecessors)
                m_newBlock.predecessors.push_back(pred->start);
            m_splitAt = 0;
            m_newBlock.baseReg = getBaseReg(predecessors);
            m_jumpTableState = -1;

            Disassemble(m_text + (rva - m_textVa), rva, m_textSize, [this](const _CodeInfo &ci, Rva va, const _DInst &dinst)
            { 
                return this->GatherNewTargets(ci, va, dinst); 
            });

            auto newbb = new BasicBlock(m_newBlock);

            if (newbb->baseReg != R_NONE && newbb->baseRegClobbered == 0)
            {
                newbb->baseRegClobbered = newbb->length;
            }

            auto targ_it = m_targets.find(newbb->start);
            if (targ_it != m_targets.end())
            {
                if (targ_it->second.targetType == TargetType::CFUNCTION || targ_it->second.targetType == TargetType::FUNCTION)
                    newbb->isFunctionStart = true;
            }

            m_basicBlocks.insert(newbb);

            if (m_splitAt > 0)
                SplitBasicBlock(newbb, m_splitAt);

            for (Rva target : m_newTargets)
            {
                //printf("New %x\n", target.ToUL());
                bool alreadyProcessed = false;
                BasicBlock tmp(target);
                auto it = m_basicBlocks.upper_bound(&tmp);
                if (it != m_basicBlocks.end())
                {
                    //printf("found %x\n", it->first);
                    if (it != m_basicBlocks.begin())
                    {
                        --it;
                        BasicBlock *bb = *it;
                        if (target >= bb->start && target < bb->start + bb->length)
                        { 
                            alreadyProcessed = true;
                            bb->predecessors.push_back(newbb->start);
                            if (target != bb->start)
                            {
                                if (bb->baseReg != R_NONE)
                                    printf("Need to split %lx - base %s, %d-%d len %d\n", target.ToUL(), GET_REGISTER_NAME(bb->baseReg), bb->baseRegSet, bb->baseRegClobbered, bb->length);
                                unsigned long splitLength = target - bb->start;
                                SplitBasicBlock(bb, splitLength);
                            }
                        }
                    }
                    else
                        printf("refound first BB!\n");
                    // TODO do the special cases
                }

                if (!alreadyProcessed)
                    AddTargetToProcess(target, newbb);
            }
                    
        }

        PropagateBaseReg();

        printf("%zd new targets\n", m_unprocessedTargets.size());
    } while (!m_unprocessedTargets.empty());
}

void BasicBlockAnalyzer::PropagateBaseReg()
{
    std::unordered_set<BasicBlock *> toBeProcessed;

    for (auto bb : m_basicBlocks)
    {
        if (bb->baseReg != R_NONE && !bb->propagated)
            toBeProcessed.insert(bb);
    }

    while (!toBeProcessed.empty())
    {
        auto bbIt = toBeProcessed.begin();
        BasicBlock *bb = *bbIt;
        //printf("Start from %lx\n", bb->start.ToUL());
        toBeProcessed.erase(bbIt);

        if (bb->baseRegClobbered < bb->length)
        { 
            //printf("clobbered....\n");
        }
        else
        { 
            for (auto successor : bb->successors)
            {
                BasicBlock tmp(successor);
                auto nextIt = m_basicBlocks.find(&tmp);
                if  (nextIt != m_basicBlocks.end())
                { 
                    BasicBlock *nextBB = *nextIt;

                    if (nextBB->propagated)
                    { 
                        //printf("Already propagated to %lx\n", nextBB->start.ToUL());
                    }
                    else if (nextBB->baseReg == R_NONE)
                    { 
                        //printf("Propagate to %lx\n", nextBB->start.ToUL());
                        toBeProcessed.insert(nextBB);
                        nextBB->baseReg = bb->baseReg;
                        nextBB->baseRegSet = 0;
                        Disassemble(m_text + (nextBB->start - m_textVa), nextBB->start, nextBB->length, 
                            [this, nextBB](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->CheckBaseRegLifetime(nextBB, ci, va, dinst); });
                        if (nextBB->baseRegClobbered == 0)
                            nextBB->baseRegClobbered = nextBB->length;
                    }
                    else
                    {
                        //printf("already done!\n");
                    }
                }
                else
                    printf("successor not found!\n");
            }
        }

        bb->propagated = true;

        if (bb->endsInIndirectJump && bb->predecessors.size() > 0)
        {
            jumpTableSize = 0;
            Disassemble(m_text + (bb->start - m_textVa), bb->start, bb->length, 
                [this, bb](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->CheckForJumpTable(bb, ci, va, dinst); });
        }
    }
}

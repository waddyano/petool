#include <mnemonics.h>
#include <unordered_set>

#include "BasicBlock.h"
#include "BasicBlockAnalyzer.h"
#include "Disassemble.h"

void BasicBlockAnalyzer::AddSuccessor(Rva r)
{
    if (m_newBlock.nSuccessors < 2)
        m_newBlock.successors[m_newBlock.nSuccessors++] = r;
    else
        printf("exceedded 2 successors!\n");
}

bool BasicBlockAnalyzer::CheckBaseRegLifetime(const _CodeInfo &ci, Rva va, const _DInst dinst)
{
    if ((dinst.flags & FLAG_DST_WR) != 0 && dinst.ops[0].type == O_REG && dinst.ops[0].index == m_newBlock.baseReg)
    { 
    	Rva a = va + dinst.addr;

        printf("Lifetime Clobber! %lx - %d\n", m_newBlock.start.ToUL(), m_newBlock.baseRegSet);
        m_newBlock.baseRegClobbered = a - m_newBlock.start;
        return false;
    }
    return true;
}

bool BasicBlockAnalyzer::GatherNewTargets(const _CodeInfo &ci, Rva va, const _DInst dinst)
{
	Rva a = va + dinst.addr;

    if ((dinst.flags & FLAG_DST_WR) != 0 && dinst.ops[0].type == O_REG && dinst.ops[0].index == m_newBlock.baseReg && m_newBlock.baseRegClobbered == 0)
    { 
        printf("Clobber! %lx - %d at %lx\n", m_newBlock.start.ToUL(), m_newBlock.baseRegSet, a.ToUL());
        m_newBlock.baseRegClobbered = a - m_newBlock.start;
    }

    m_newBlock.length += dinst.size;

    unsigned int mfc = META_GET_FC(dinst.meta);

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
                    printf("LEA %lx - %d\n", m_newBlock.start.ToUL(), m_newBlock.baseRegSet);
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
				it->second.targetType = type;
            if (mfc == FC_CND_BRANCH)
            { 
                AddSuccessor(target);
            }
        }
	}

    Rva fallThruTarget = va + dinst.addr + dinst.size;
    if (mfc != FC_NONE && mfc != FC_UNC_BRANCH && mfc != FC_RET && mfc != FC_CALL)
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


    return cont;
}

void BasicBlockAnalyzer:: SplitBasicBlock(BasicBlock *bb, unsigned long splitOffset)
{
    Rva split = bb->start + splitOffset;
    BasicBlock *splitBB = new BasicBlock(split, bb->length - splitOffset);
    splitBB->nSuccessors = bb->nSuccessors;
    for (int i = 0; i < bb->nSuccessors; ++i)
        splitBB->successors[i]= bb->successors[i];
    bb->nSuccessors = 1;
    bb->successors[0] = split;
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

void BasicBlockAnalyzer::Analyze(std::set<Rva> &&seedRvas)
{
    m_unprocessedTargets = std::move(seedRvas);
    while (!m_unprocessedTargets.empty())
    {
        Rva rva = *m_unprocessedTargets.begin();

        m_unprocessedTargets.erase(rva);

        if (rva < m_textVa || rva >= m_textVa + m_textSize)
        {
            continue;
        }

        //printf("start at %lx\n", rva.ToUL());
        m_newTargets.clear();

        m_newBlock = BasicBlock(rva);
        m_splitAt = 0;

        Disassemble(m_text + (rva - m_textVa), rva, m_textSize, [this](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->GatherNewTargets(ci, va, dinst); });

        auto newbb = new BasicBlock(m_newBlock);

        if (newbb->baseReg != R_NONE && newbb->baseRegClobbered == 0)
        {
            newbb->baseRegClobbered = newbb->length;
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
                m_unprocessedTargets.insert(target);
        }
    }

    PropagateBaseReg();
}

void BasicBlockAnalyzer::PropagateBaseReg()
{
    std::unordered_set<BasicBlock *> toBeProcessed;

    for (auto bb : m_basicBlocks)
    {
        if (bb->baseReg != R_NONE)
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
            for (int i = 0; i < bb->nSuccessors; ++i)
            {
                //printf("Propagate to %lx\n", bb->successors[i].ToUL());
                BasicBlock tmp(bb->successors[i]);
                auto nextIt = m_basicBlocks.find(&tmp);
                if (nextIt != m_basicBlocks.end())
                { 
                    BasicBlock *nextBB = *nextIt;
                    if (nextBB->baseReg == R_NONE)
                    { 
                        toBeProcessed.insert(nextBB);
                        nextBB->baseReg = bb->baseReg;
                        nextBB->baseRegSet = 0;
                        Disassemble(m_text + (nextBB->start - m_textVa), nextBB->start, nextBB->length, 
                            [this](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->CheckBaseRegLifetime(ci, va, dinst); });
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
    }
}
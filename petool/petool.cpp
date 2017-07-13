#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <distorm.h>
#include <algorithm>
#include <functional>
#include <sstream>
#include <map>
#include <mnemonics.h>
#include <set>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "BasicBlock.h"
#include "BasicBlockAnalyzer.h"
#include "ConfigFile.h"
#include "Disassemble.h"
#include "Exception.h"
#include "Imports.h"
#include "Options.h"
#include "RTTI.h"
#include "Rva.h"
#include "Target.h"
#include "Unwind.h"

static const char *directoryNames[] =
{
	"IMAGE_DIRECTORY_ENTRY_EXPORT",
	"IMAGE_DIRECTORY_ENTRY_IMPORT",
	"IMAGE_DIRECTORY_ENTRY_RESOURCE",
	"IMAGE_DIRECTORY_ENTRY_EXCEPTION",
	"IMAGE_DIRECTORY_ENTRY_SECURITY",
	"IMAGE_DIRECTORY_ENTRY_BASERELOC",
	"IMAGE_DIRECTORY_ENTRY_DEBUG",
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
	"IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",
	"IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
	"IMAGE_DIRECTORY_ENTRY_TLS",
	"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
	"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
	"IMAGE_DIRECTORY_ENTRY_IAT",
	"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
	"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
	"??"
};

class PEFile
{
public:
	PEFile(const char *filename, const Options &options) : m_options(options)
	{
        memset(&dummySection, 0, sizeof(dummySection));
        strcpy((char *)dummySection.Name, "**dum**");

		FILE *fp = fopen(filename, "rb");

		if (fp == NULL)
		{
			ThrowBadFile("can not open\n");
			return;
		}

		fseek(fp, 0, SEEK_END);
		m_originalLength = ftell(fp);
		//printf("length %d x%x\n", (int)m_originalLength, (int)m_originalLength);
		fseek(fp, 0, SEEK_SET);
		m_base = static_cast<unsigned char *>(malloc(m_originalLength));
		if (fread(m_base, 1, m_originalLength, fp) != m_originalLength)
			printf("failed to read\n");
		fclose(fp);

        Initialize();
	}

    bool Write(const char *filename)
    {
        FILE *fp = fopen(filename, "wb");
        if (fp == nullptr)
            return false;
        size_t off = 0;
        size_t len = (unsigned char *)m_sectionHeaders - m_base;
        fwrite(m_base, 1, len, fp);
        off += len;

        for (auto & s : m_sections)
        {
           fwrite(&s.m_section, 1, sizeof(s.m_section), fp);
           off += sizeof(s.m_section);
        }

        size_t left = 0x400 - off;
        printf("%zd zeroes\n", left);

        for (size_t i = 0; i < left; ++i)
        {
            unsigned char z = 0;
            fwrite(&z, 1, 1, fp);
            off += 1;
        }

        for (auto & s : m_sections)
        {
            fwrite(s.m_rawData, s.m_section.SizeOfRawData, 1, fp);
            off += s.m_section.SizeOfRawData;
        }

        fclose(fp);
        return true;
    }

	DWORD Rva2Offset(unsigned long rva)
    {
        return Rva2Offset(Rva(rva));
    }

	DWORD Rva2Offset(Rva rva)
	{
		if (rva.IsZero())
		{
			return 0;
		}

		PIMAGE_SECTION_HEADER sh = Rva2Section(rva);
        if (sh == nullptr)
            return 0;

  		return rva.ToUL() - sh->VirtualAddress + sh->PointerToRawData;
	}

    IMAGE_SECTION_HEADER dummySection;

	PIMAGE_SECTION_HEADER Rva2Section(unsigned long rva)
    {
        return Rva2Section(Rva(rva));
    }

	PIMAGE_SECTION_HEADER Rva2Section(Rva rva)
	{
		if (rva.ToUL() == 0)
		{
			return &dummySection;
		}

		SECTION *sh = &m_sections[0];

		for (int i = 0; i < m_sections.size(); i++)
		{
			if (rva >= Rva(sh->m_section.VirtualAddress) && rva < Rva(sh->m_section.VirtualAddress + sh->m_section.Misc.VirtualSize))
			{
        		return &sh->m_section;
			}

			++sh;
		}

		return &dummySection;
	}

	template <class T>
	T *Rva2Ptr(Rva rva)
	{
		if (rva.IsZero())
		{
			return nullptr;
		}

		SECTION *sh = &m_sections[0];

		for (int i = 0; i < m_sections.size(); i++)
		{
			if (rva >= Rva(sh->m_section.VirtualAddress) && rva < Rva(sh->m_section.VirtualAddress + sh->m_section.Misc.VirtualSize))
			{
        		return reinterpret_cast<T *>(sh->m_rawData + rva.ToUL() - sh->m_section.VirtualAddress);
			}

			++sh;
		}

		return 0;
	}

	Rva Ptr2Rva(void *ptr)
	{
		if (ptr == nullptr)
		{
			return Rva();
		}

		SECTION *sh = &m_sections[0];

        unsigned char *pc = static_cast<unsigned char *>(ptr);

		for (int i = 0; i < m_sections.size(); i++)
		{
            if (pc >= sh->m_rawData && pc < sh->m_rawData + sh->m_section.Misc.VirtualSize)
			{
        		return Rva(sh->m_section.VirtualAddress) + (pc - sh->m_rawData);
			}

			++sh;
		}

		return Rva();
	}

    template <class T>
	T *Rva2Ptr(unsigned long long rva)
    {
        return Rva2Ptr<T>(Rva(rva));
    }

    template <class T>
    bool GetTopBit(T i)
    {
        return (i >> (sizeof(T) * CHAR_BIT - 1)) != 0;
    }

    template <class T>
    T ClearTopBit(T i)
    {
        return i & ~( (T)1 << (sizeof(T) * CHAR_BIT - 1));
    }

	void PrintThunkData(Rva va, IMAGE_THUNK_DATA *thunkData)
	{
        if (thunkData->u1.AddressOfData == 0)
            printf("Empty thunks\n");
		while (thunkData->u1.AddressOfData != 0)
		{
            bool isOrdinal = GetTopBit(thunkData->u1.AddressOfData);

            if (isOrdinal)
            {
                printf("  Ordinal: %llu\n", ClearTopBit(thunkData->u1.AddressOfData));
            }
            else
            {
			    IMAGE_IMPORT_BY_NAME *iin = Rva2Ptr<IMAGE_IMPORT_BY_NAME>(Rva(thunkData->u1.AddressOfData));
                if (iin == nullptr)
                {
                    printf("bad iin!\n");
                    return;
                }
			    printf("  %s %lx %x va %lx in %s\n", iin->Name, va.ToUL(), iin->Hint, (DWORD)thunkData->u1.AddressOfData, 
                    Rva2Section(Rva(thunkData->u1.AddressOfData))->Name);
            }
			++thunkData;
            va += sizeof(*thunkData);
		}
	}

	void GatherImportedSymbols(Rva va, const char *dllName, IMAGE_THUNK_DATA *thunkData)
	{
        ImportedDLL *importedDLL = m_importedDLLs.AddImportedDLL(dllName);

		while (thunkData->u1.AddressOfData != 0)
		{
           bool isOrdinal = GetTopBit(thunkData->u1.AddressOfData);

            if (isOrdinal)
            {
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "Ordinal %llu", ClearTopBit(thunkData->u1.AddressOfData));
    			//printf("Imported %016llx %s\n", m_imageBase + va, n);
                m_importedDLLs.AddImportedSymbol(importedDLL, tmp, va);
			    //m_vaToImportedSymbols.insert(std::make_pair(va, tmp));
                //m_importedSymbols.insert(std::make_pair(tmp, va));
            }
            else
            {
                IMAGE_IMPORT_BY_NAME *iin = Rva2Ptr<IMAGE_IMPORT_BY_NAME>(thunkData->u1.AddressOfData);
                if (iin == nullptr)
                {
                    printf("bad iin!\n");
                    return;
                }
                m_importedDLLs.AddImportedSymbol(importedDLL, iin->Name, va);
			    //m_vaToImportedSymbols.insert(std::make_pair(va, iin->Name));
                //m_importedSymbols.insert(std::make_pair(iin->Name, va));
    			//printf("Imported %016llx %s\n", m_imageBase + va, iin->Name);
            }

			++thunkData;
			va += sizeof(IMAGE_THUNK_DATA);
		}
	}

	void GatherImportedSymbols()
	{
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
		{
			IMAGE_IMPORT_DESCRIPTOR *descs = Rva2Ptr<IMAGE_IMPORT_DESCRIPTOR>(Rva(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
			IMAGE_IMPORT_DESCRIPTOR *desc = descs;
			while (desc->Name != 0)
			{
				GatherImportedSymbols(Rva(desc->FirstThunk), Rva2Ptr<const char>(desc->Name), Rva2Ptr<IMAGE_THUNK_DATA>(desc->FirstThunk));
				++desc;
			}
		}
	}

    void GatherDelayImportedSymbols()
    {
        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 0)
            return;

        IMAGE_DELAYLOAD_DESCRIPTOR *descs = Rva2Ptr<IMAGE_DELAYLOAD_DESCRIPTOR>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

		IMAGE_DELAYLOAD_DESCRIPTOR *desc = descs;
		while (desc->DllNameRVA != 0)
		{
			char *name = Rva2Ptr<char>(desc->DllNameRVA);
            GatherImportedSymbols(Rva(desc->ImportNameTableRVA), Rva2Ptr<IMAGE_THUNK_DATA>(desc->ImportNameTableRVA));

            ++desc;
		}
    }


	void GatherExportedSymbols()
	{
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
		{
			IMAGE_EXPORT_DIRECTORY *exports = Rva2Ptr<IMAGE_EXPORT_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			DWORD *addressOfNames = Rva2Ptr<DWORD>(exports->AddressOfNames);
			DWORD *addressOfFunctions = Rva2Ptr<DWORD>(exports->AddressOfFunctions);
			for (unsigned int i = 0; i < exports->NumberOfNames; ++i)
			{
				char *name = Rva2Ptr<char>(addressOfNames[i]);
				//printf("%s %lx\n", name, addressOfFunctions[i]);
				m_exportedSymbols.insert(std::make_pair(Rva(addressOfFunctions[i]), name));
			}
		}
	}

    void PrintExports()
	{
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
		{
			IMAGE_EXPORT_DIRECTORY *exports = Rva2Ptr<IMAGE_EXPORT_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			DWORD *addressOfNames = Rva2Ptr<DWORD>(exports->AddressOfNames);
			DWORD *addressOfFunctions = Rva2Ptr<DWORD>(exports->AddressOfFunctions);
			for (unsigned int i = 0; i < exports->NumberOfNames; ++i)
			{
				char *name = Rva2Ptr<char>(addressOfNames[i]);
				printf("%s %lx\n", name, addressOfFunctions[i]);
			}
		}
	}

  	void GatherRelocationTargets()
	{
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
		{
			IMAGE_BASE_RELOCATION *reloc = Rva2Ptr<IMAGE_BASE_RELOCATION>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			DWORD sizeLeft = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			while (sizeLeft > 0)
			{
                if (reloc->SizeOfBlock == 0)
                {
                    printf("bad reloc!\n");
                    return;
                }
				sizeLeft -= reloc->SizeOfBlock;
                WORD *r = (WORD *)(reloc + 1);
                int nRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (int i = 0; i < nRelocs; ++i)
                {
                    unsigned int relType = r[i] >> 12;
                    unsigned int relOffset = r[i] & 0xfff;
                    if (relType == 0)
                        continue;
                    if (relType == IMAGE_REL_BASED_DIR64)
                    {
                        m_relocations.insert(Rva(reloc->VirtualAddress + relOffset));
                        ULONGLONG va = *Rva2Ptr<ULONGLONG>(reloc->VirtualAddress + relOffset);
                        auto rva = Rva((unsigned long)(va - m_imageBase));
                        auto s = Rva2Section(rva);
                        if (s != nullptr && strcmp((const char *)s->Name, ".text") == 0)
                        {
                            m_targets.insert(std::make_pair(rva, TargetInfo(TargetType::RFUNCTION)));
                        }
                    }
                    else
                    {
                        printf("reltype %d!\n", relType);
                    }
                }

				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<char *>(reloc) + reloc->SizeOfBlock);
			}
		}
	}

    void GatherFunctionTable()
    {
        int sectionNo = FindSection(".pdata");
        if (sectionNo < 0)
            return;
        DWORD nEntries = m_sections[sectionNo].m_section.SizeOfRawData / 12;
        RUNTIME_FUNCTION *entries = (RUNTIME_FUNCTION *)m_sections[sectionNo].m_rawData;
        for (DWORD i = 0; i < nEntries; ++i)
        {
            RUNTIME_FUNCTION &entry = entries[i];
            if (entry.BeginAddress == 0)
                break;
            auto ui = Rva2Ptr<UNWIND_INFO>(entry.UnwindInfoAddress);
            if ((ui->Flags & UNW_FLAG_CHAININFO) == 0)
                m_targets.insert(std::make_pair(Rva(entry.BeginAddress), TargetInfo(TargetType::FUNCTION, true)));
            if ((ui->Flags & UNW_FLAG_EHANDLER) != 0)
            {
                m_targets.insert(std::make_pair(Rva(ui->GetHandlerInfo().EHandler.ExceptionHandler), TargetInfo(TargetType::FUNCTION, true)));
            }
        }
    }

    // Find basic block starting at the given Rva - return null if not found
    BasicBlock *FindBasicBlock(Rva a)
    {
        BasicBlock tmp(a);
        auto it = m_basicBlocks.find(&tmp);
        if (it != m_basicBlocks.end())
        {
            BasicBlock *bb = *it;
            return bb;
        }
        return nullptr;
    }

	void AdjustRIPOperand(const _CodeInfo &ci, Rva va, _DInst dinst, BasicBlock *bb)
    {
        Rva a = va + dinst.addr;

        int operandOffset = dinst.size;
        int opSize = 4;
        int skippedOp = 128;
        bool pcRel = false;
        bool adjustDisp = false;
        bool setLastInst = false;
		for (int j = OPERANDS_NO - 1; j >= 0; --j)
		{
			if (dinst.ops[j].type == O_NONE)
				continue;
			if (dinst.ops[j].type == O_PC)
			{
                operandOffset -= dinst.ops[j].size / 8;
                opSize = dinst.ops[j].size / 8;
                pcRel = true;
                break;
			}
			else if (dinst.ops[j].type == O_SMEM && (dinst.flags & FLAG_RIP_RELATIVE) != 0)
            {
                if ((dinst.ops[j].size & 7) != 0)
                    printf("oh my\n");
                if (skippedOp != 128)
                    printf("oh me %d\n", skippedOp);
                if (dinst.dispSize != 32)
                    printf("smem size %d\n", dinst.dispSize / 8);
                operandOffset -= dinst.dispSize / 8;
                opSize = dinst.dispSize / 8;
                break;
            }
            else if (dinst.ops[j].type == O_IMM)
            {
                if ((dinst.ops[j].size & 7) != 0)
                    printf("oh my\n");
                operandOffset -= dinst.ops[j].size / 8;
            }
            else if (dinst.ops[j].type == O_REG && j == 0 && dinst.opcode == I_LEA &&
                (dinst.ops[1].type == O_MEM  || dinst.ops[1].type == O_SMEM))

            {
                if ((int64_t)dinst.disp > 0)
                { 
                    Rva b = Rva(dinst.disp);
                    if (AdjustRva(&b))
                    { 
                        printf("stashed instruction\n");
                        Printer(ci, va, dinst);
                        m_lastInst = dinst;
                        setLastInst = true;
                        operandOffset = dinst.size - dinst.dispSize / 8;
                    }
                }
            }
            else if (dinst.ops[j].type == O_REG)
            {
            }
            else if ((dinst.ops[j].type == O_MEM && ((dinst.base != R_NONE && dinst.base == bb->baseReg) || (dinst.ops[j].index != R_NONE && dinst.ops[j].index == bb->baseReg))) ||
                     (dinst.ops[j].type == O_SMEM && dinst.ops[j].index == bb->baseReg))
            {
                unsigned long off = a - bb->start;
                if (off >= bb->baseRegSet && off < bb->baseRegClobbered)
                {
                    Rva b = Rva(dinst.disp);
                    if (m_options.Verbose)
                    {
                        printf("using base! %llx\n", dinst.disp);
                        Printer(ci, va, dinst);
                    }
                    if (AdjustRva(&b))
                    {
                        if (m_options.Verbose)
                            printf("needed adjust!\n");
                        adjustDisp = true;
                        operandOffset -= dinst.dispSize / 8;
                    }
                }
                skippedOp = dinst.ops[j].type;
            }
            else
            {
                skippedOp = dinst.ops[j].type;
            }
        }

        if (!setLastInst)
        { 
            if (m_lastInst.flags != FLAG_NOT_DECODABLE)
            {
                if (dinst.opcode == I_ADD && 
                    dinst.ops[0].type == O_REG && dinst.ops[0].index == m_lastInst.ops[0].index &&
                    dinst.ops[1].type == O_REG && dinst.ops[1].index == bb->baseReg)
                {
                    printf("need to adjust last\n");
                    adjustDisp = true;
                    dinst = m_lastInst;
                    operandOffset = m_lastOperandOffset;
                }
            }

            m_lastInst.flags = FLAG_NOT_DECODABLE;
        }
        else
        {
            m_lastOperandOffset = operandOffset;
        }


        if (operandOffset == dinst.size && !adjustDisp)
            return;

        if (opSize != 4 && !adjustDisp)
        {
            Rva targetVa = va + (pcRel ? INSTRUCTION_GET_TARGET(&dinst) : INSTRUCTION_GET_RIP_TARGET(&dinst));
            Rva oldTargetVa = targetVa;
            if (AdjustRva(&targetVa))
                printf("can not handle op off %d/%d size %d at %x - %d\n", operandOffset, dinst.size, opSize, (DWORD)(va.ToUL() + dinst.addr), pcRel);
            return;
        }

        if (adjustDisp)
        {
            if (m_options.Verbose)
			    printf("Instr at %lx: Adjust disp\n", (va + dinst.addr).ToUL());

            DWORD *dispLoc = Rva2Ptr<DWORD>((va + dinst.addr).ToUL() + operandOffset);
            unsigned long newDisp = (unsigned long)dinst.disp;
            AdjustRva(&newDisp);
            memcpy(dispLoc, &newDisp, 4);
            _DInst tmp(dinst);
            tmp.disp = newDisp;

            if (m_options.Verbose)
                Printer(ci, va, tmp);
            return;
        }

        if ((dinst.flags & FLAG_RIP_RELATIVE) != 0 || pcRel)
        {
            Rva targetVa = va + (pcRel ? INSTRUCTION_GET_TARGET(&dinst) : INSTRUCTION_GET_RIP_TARGET(&dinst));
            Rva oldTargetVa = targetVa;

            if (AdjustRva(&targetVa))
            {
                if (m_options.Verbose)
                    printf("Instr at %lx: Adjust %s[%0lx]\n", (va + dinst.addr).ToUL(), pcRel ? "pc" : "smem", targetVa.ToUL());
                int newDisp = (int)(dinst.disp + (targetVa - oldTargetVa));
                DWORD *dispLoc = Rva2Ptr<DWORD>((va + dinst.addr).ToUL() + operandOffset);
                if (dispLoc == nullptr)
                    printf("Current disp null new disp %x\n", newDisp);
                else
                {
                    memcpy(dispLoc, &newDisp, 4);
                    _DInst tmp(dinst);
                    tmp.disp = newDisp;
                    if (m_options.Verbose)
                        Printer(ci, va, tmp);
                }
            }
        }
    }

    unsigned long long ToVa(Rva r)
    {
        return m_imageBase + r.ToUL();
    }

    bool LooksLikeString(const char *s)
    {
        const char *p = s;
        while (*p != '\0')
        {
            if (!isascii(*p))
                return false;
            ++p;
        }

        return p - s > 4;
    }

    void PrintString(const char *s)
    {
        while (*s != '\0')
        {
            if (iscntrl(*s))
            {
                if (*s == '\n')
                    printf("\\n");
                else
                    printf("\\x%02x", 0xff & *s);
            }
            else
                printf("%c", *s);
            ++s;
        }
    }

	bool Printer(const _CodeInfo &ci, Rva va, const _DInst dinst)
	{
		_DecodedInst decoded;
		distorm_format(&ci, &dinst, &decoded);
		_strlwr(reinterpret_cast<char *>(decoded.instructionHex.p));
		_strlwr(reinterpret_cast<char *>(decoded.mnemonic.p));
		if (decoded.operands.length > 0)
			_strlwr(reinterpret_cast<char *>(decoded.operands.p));
		Rva a = va + decoded.offset;

        BasicBlock *bb = FindBasicBlock(a);
		if (bb != nullptr)
		{
			//printf("%s%u:\n", ToString(it->second.targetType), it->second.label);
			printf("%s:\n", bb->GetLabel().c_str());
		}

		printf("%0*I64x %-24s %s%s%s", 16, ToVa(a),
			(char*)decoded.instructionHex.p, (char*)decoded.mnemonic.p,
			decoded.operands.length != 0 ? " " : "", (char*)decoded.operands.p);
		for (int j = 0; j < OPERANDS_NO; ++j)
		{
			if (dinst.ops[j].type == O_NONE)
				break;
			Rva target = Rva::Invalid();
			if (dinst.ops[j].type == O_PC)
			{
				target = va + INSTRUCTION_GET_TARGET(&dinst);
				printf(" pc %016llx", ToVa(target));
			}
			if (dinst.ops[j].type == O_SMEM && (dinst.flags & FLAG_RIP_RELATIVE) != 0)
			{
				target = va + INSTRUCTION_GET_RIP_TARGET(&dinst);
				printf(" smem[%016llx]", ToVa(target));
			}
			if (target != Rva::Invalid())
			{
				BasicBlock *t = FindBasicBlock(target);
				if (t != nullptr)
					//printf(" %s%u.", ToString(it->second.targetType), it->second.label);
                    printf(" %s", t->GetLabel().c_str());

                const char * symbol = m_importedDLLs.Find(target);
                if (symbol != nullptr)
					printf(" %s", symbol);
				//auto importIt = m_vaToImportedSymbols.find(target);
				//if (importIt != m_vaToImportedSymbols.end())
					//printf(" %s", importIt->second.c_str());

                auto section = Rva2Section(target);
                if (section != &dummySection && !IsExecutable(*section) && !IsWritable(*section))
                {
                    char *s = Rva2Ptr<char>(target);
                    if (LooksLikeString(s))
                    {
                        printf(" \"");
                        PrintString(s);
                        printf("\"");
                    }
                }
			}
		}
		printf("\n");

        return dinst.opcode != I_JMP && dinst.opcode != I_RET;
	}


    void ThrowBadFile(const char *msg)
    {
        fprintf(stderr, "problem with %s\n", msg);
        throw "bad exe file";
    }

    void Initialize()
    {
		IMAGE_DOS_HEADER *header = reinterpret_cast<IMAGE_DOS_HEADER *>(m_base);

        if (header->e_magic != IMAGE_DOS_SIGNATURE)
            ThrowBadFile("magic");

        if (header->e_lfanew < sizeof(IMAGE_DOS_HEADER) || header->e_lfanew > m_originalLength)
            ThrowBadFile("e_lfanew");

		DWORD *signature = reinterpret_cast<DWORD *>(m_base + header->e_lfanew);

		IMAGE_FILE_HEADER *fileHeader = reinterpret_cast<IMAGE_FILE_HEADER *>(signature + 1);

        if (fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
            ThrowBadFile("not 64 bit");

        if ((fileHeader->Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)
            ThrowBadFile("can not instrument .EXE stripped of relocations");

		m_optionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 *>(fileHeader + 1);

        if (((m_optionalHeader->DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0)
            printf("High Entropy VA\n");

        if (((m_optionalHeader->DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0)
            printf("Dynamic Base\n");

        if (((m_optionalHeader->DllCharacteristics) & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0)
            printf("NX Compat\n");

		printf("Machine %x\n", fileHeader->Machine);
		printf("# sections %d\n", fileHeader->NumberOfSections);
		printf("sym tab %d\n", fileHeader->PointerToSymbolTable);
		printf("load address %llx\n", m_optionalHeader->ImageBase);
		m_imageBase = m_optionalHeader->ImageBase;
        m_newImageBase = m_options.FixedAddress ? 0x500000000 : m_imageBase;
        printf("Entry %x\n", m_optionalHeader->AddressOfEntryPoint);
        printf("SizeImage %lx SizeHeaders %lx\n", m_optionalHeader->SizeOfImage, m_optionalHeader->SizeOfHeaders);

		m_nSections = fileHeader->NumberOfSections;
		m_sectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(m_optionalHeader + 1);

        printf("Image Header %p => %p\n", m_base, m_sectionHeaders);
        printf("Sections %p => %p\n", m_sectionHeaders, m_sectionHeaders + m_nSections);
        printf("H+S size %zd\n", (unsigned char *)(m_sectionHeaders + m_nSections) - m_base);
        BuildSections(m_nSections, m_sectionHeaders);

        DumpDebugDirectory();
    }

    void DumpDebugDirectory()
    {
        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size != 0)
		{
			IMAGE_DEBUG_DIRECTORY *debug = Rva2Ptr<IMAGE_DEBUG_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
            printf("debug %x\n", debug->AddressOfRawData);
        }
    }

    int FindSection(const char *name)
    {
		for (int i = 0; i < m_nSections; ++i)
		{
			const IMAGE_SECTION_HEADER &head = m_sectionHeaders[i];
			if (strcmp((const char *)head.Name, name) == 0)
			{
                return i;
			}
		}

        return -1;
    }

    void GatherAllTargets()
    {
        int textSection = FindSection(".text");
        if (textSection < 0)
        {
            printf("no text section\n");
            return;
        }
		Rva textVa(m_sectionHeaders[textSection].VirtualAddress);
		DWORD textSize = m_sectionHeaders[textSection].SizeOfRawData;

        m_targets.clear();
        if (!m_basicBlocks.empty())
            printf("Need to free!\n");
        m_basicBlocks.clear();

		GatherImportedSymbols();
        GatherDelayImportedSymbols();

#if 0
        auto it = m_importedSymbols.find("_CxxThrowException");
        if (it != m_importedSymbols.end())
        {
            printf("throws exception! %lx\n", it->second.ToUL());
        }
#endif

		GatherExportedSymbols();

        if (m_optionalHeader->AddressOfEntryPoint != 0)
        {
            m_targets.insert(std::make_pair(Rva(m_optionalHeader->AddressOfEntryPoint), TargetInfo(TargetType::ENTRY)));
        }

        GatherFunctionTable();
        GatherRelocationTargets();

		if (!textVa.IsZero())
		{
            std::set<Rva> seedRvas;

            for (const auto &e : m_targets)
            { 
                seedRvas.insert(e.first); 
            }

            for (const auto &e : m_exportedSymbols)
            {
                seedRvas.insert(e.first); 
            }

            BasicBlockAnalyzer analyzer(Rva2Ptr<unsigned char>(textVa), textVa, textSize, m_relocations);
            analyzer.SetVerbose(m_options.Verbose);

            bool first = true;
            Rva indirectThrowException;

            while (!seedRvas.empty())
            {
                analyzer.Analyze(std::move(seedRvas));
                seedRvas.clear();
                m_basicBlocks = analyzer.GetBasicBlocks();

                if (first)
                {
                    for (BasicBlock *b : m_basicBlocks)
                    {
                        if (!b->isJumpTable)
                        {
			                Disassemble(Rva2Ptr<unsigned char>(b->start), b->start, b->length, 
                                [this, b](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->CheckForJumpToImport(ci, va, dinst, b); });

                            if (b->label == "_CxxThrowException*")
                                indirectThrowException = b->start;

		                    auto it = m_exportedSymbols.find(b->start);
		                    if (it != m_exportedSymbols.end())
                                b->label = it->second;
                        }
                    }
                }

                if (indirectThrowException != Rva::Invalid())
                { 
                    for (BasicBlock *b : m_basicBlocks)
                    {
                        if (b->containsCall)
                        {
                            rdxValue = Rva::Invalid();

			                Disassemble(Rva2Ptr<unsigned char>(b->start), b->start, b->length, 
                                [this, b, indirectThrowException](const _CodeInfo &ci, Rva va, const _DInst &dinst) 
                                { 
                                    return this->CheckForThrowException(ci, va, dinst, b, indirectThrowException); 
                                });
                        }
                    }

                    printf("Found %zd throws!\n", throwInfoObjects.size());
                    for (Rva throwInfo : throwInfoObjects)
                    {
                        printf("throw info %lx\n", throwInfo.ToUL());
                        ThrowInfo *ti = Rva2Ptr<ThrowInfo>(throwInfo);
                        printf("destr %lx\n", ti->destructorOffset);
                        if (ti->destructorOffset != 0)
                        {
                            Rva va((unsigned long)ti->destructorOffset);
                            BasicBlock *dbb = FindBasicBlock(Rva((unsigned long)ti->destructorOffset));
                            if (dbb == nullptr)
                            {
                                printf("Destructor is new seed!\n");
                                seedRvas.insert(va);
                            }
                        }

                        if (m_options.Verbose)                      
                            printf("catchable %x\n", ti->catchableTypeArrayOffset);
                        m_dataToAdjust.insert(throwInfo + offsetof(ThrowInfo, catchableTypeArrayOffset));
                        CatchableTypeArray *cta = Rva2Ptr<CatchableTypeArray>(ti->catchableTypeArrayOffset);
                        if (m_options.Verbose)
                            printf("array length %u\n", cta->count);
                        for (unsigned int i = 0; i < cta->count; ++i)
                        {
                            if (m_options.Verbose)
                                printf("%u\n", cta->catchableTypeOffsets[i]);

                            m_dataToAdjust.insert(Rva(ti->catchableTypeArrayOffset + offsetof(CatchableTypeArray, catchableTypeOffsets) + i * sizeof(unsigned int)));
                            CatchableType *ct = Rva2Ptr<CatchableType>(cta->catchableTypeOffsets[i]);
                            if (m_options.Verbose)
                                printf("ct %u tdo %x %u %u %u copy %x\n", ct->a, ct->typeDescriptorOffset, ct->c, ct->d, ct->e, ct->copyConstructorOffset);
                            if (ct->copyConstructorOffset != 0)
                            {
                                Rva va((unsigned long)ct->copyConstructorOffset);
                                BasicBlock *cbb = FindBasicBlock(va);
                                if (cbb == nullptr)
                                {
                                    printf("Copy constructor is new seed!\n");
                                    seedRvas.insert(va);
                                }
                            }
                            if (ct->typeDescriptorOffset != 0)
                            {
                                m_dataToAdjust.insert(Rva(cta->catchableTypeOffsets[i] + offsetof(CatchableType, typeDescriptorOffset)));
                                auto descriptor = Rva2Ptr<RTTITypeDescriptor>(ct->typeDescriptorOffset);
                                if (m_options.Verbose)
                                    printf("name %s\n", descriptor->name);
                            }
                        }
                    }
                }

                first = false;
            }

            for (auto p : analyzer.GetTargets())
            {
                auto it = m_targets.find(p.first);
                if (it != m_targets.end())
                {
                    if (p.second.targetType == TargetType::CFUNCTION && it->second.targetType != TargetType::FUNCTION)
                        it->second.targetType = TargetType::CFUNCTION;
                }
                else
                {
                    m_targets.insert(p);
                }
            }

            for (auto vt : analyzer.GetPossibleVtables())
            {
                auto loc1 = Rva2Ptr<uint64_t >(vt - 8);
                if (m_options.Verbose)
                    printf("check vt %lx\n", vt.ToUL());
                auto loc2 = Rva2Ptr<uint64_t >(vt);
                auto s1 = Rva2Section((unsigned long)(*loc1 - m_imageBase));
                auto s2 = Rva2Section((unsigned long)(*loc2 - m_imageBase));
                if (!IsExecutable(*s1) && IsExecutable(*s2))
                {
                    unsigned long locatorOffset = (unsigned long)(*loc1 - m_imageBase);
                    auto locator = Rva2Ptr<RTTIObjectLocator>(locatorOffset);

                    if (m_options.Verbose)
                        printf("locator offs %lu %lu\n", locatorOffset, locator->selfOffset);
                    if (locatorOffset == locator->selfOffset)
                    {
                        m_dataToAdjust.insert(Rva(locatorOffset + offsetof(RTTIObjectLocator, typeDescriptorOffset)));
                        m_dataToAdjust.insert(Rva(locatorOffset + offsetof(RTTIObjectLocator, classHierarchyDescriptorOffset)));
                        m_dataToAdjust.insert(Rva(locatorOffset + offsetof(RTTIObjectLocator, selfOffset)));

                        if (m_options.Verbose)
                            printf("locator tdo %lx - offsets %lx %lx\n", locator->typeDescriptorOffset, locatorOffset, locator->selfOffset);

                        auto descriptor = Rva2Ptr<RTTITypeDescriptor>(locator->typeDescriptorOffset);

                        if (m_options.Verbose)
                            printf("desc name %s\n", descriptor->name);

                        auto base = Rva2Ptr<RTTIClassHierarchyDescriptor>(locator->classHierarchyDescriptorOffset);
                        auto bases = Rva2Ptr<unsigned int>(base->baseClassArrayOffset);
                        m_dataToAdjust.insert(Rva(locator->classHierarchyDescriptorOffset + offsetof(RTTIClassHierarchyDescriptor, baseClassArrayOffset)));
                        for (unsigned int i = 0; i < base->arrayLength; ++i)
                        {
                            if (m_options.Verbose)
                                printf("  base: %lx ", bases[i]);
                            auto x = Rva2Ptr<RTTIBaseClassDescriptor>(bases[i]);
                            m_dataToAdjust.insert(Rva(base->baseClassArrayOffset + i * sizeof(unsigned int)));
                            if (m_options.Verbose)
                            {
                                printf("chd %lx ", x->classHierarchyDescriptorOffset);
                                printf("tdo %lx\n", x->typeDescriptorOffset);
                            }
                            m_dataToAdjust.insert(Rva(bases[i] + offsetof(RTTIBaseClassDescriptor, classHierarchyDescriptorOffset)));
                            m_dataToAdjust.insert(Rva(bases[i] + offsetof(RTTIBaseClassDescriptor, typeDescriptorOffset)));
                            auto baseDescriptor = Rva2Ptr<RTTITypeDescriptor>(x->typeDescriptorOffset);
                            if (m_options.Verbose)
                                printf("  base name %s\n", baseDescriptor->name);
                        }
                    }
                }
            }

            int sectionNo = FindSection(".pdata");
            if (sectionNo >= 0)
            {
                DWORD nEntries = m_sections[sectionNo].m_section.SizeOfRawData / 12;
                RUNTIME_FUNCTION *entries = (RUNTIME_FUNCTION *)m_sections[sectionNo].m_rawData;
                for (DWORD i = 0; i < nEntries; ++i)
                {
                    RUNTIME_FUNCTION &entry = entries[i];
                    if (entry.BeginAddress == 0)
                        break;
                    auto s = Rva2Section(entry.UnwindInfoAddress);
                    if (s != nullptr)
                    {
                        XData *xd = nullptr;
                        auto ui = Rva2Ptr<UNWIND_INFO>(entry.UnwindInfoAddress);
                        if ((ui->Flags & UNW_FLAG_EHANDLER) != 0)
                        {
                            BasicBlock *excbb = FindBasicBlock(Rva(ui->GetHandlerInfo().EHandler.ExceptionHandler));
                            if (excbb != nullptr)
                            { 
                                if (excbb->GetLabel() == "__CxxFrameHandler3*")
                                { 
                                    xd = Rva2Ptr<XData>(ui->GetHandlerInfo().EHandler.ExceptionHandlerData);
                                }
                            }
                        }
                        if (xd != nullptr)
                        {
                            if (m_options.Verbose)
                                printf("xdata %lx %lx %lx %lx\n", xd->a, xd->unwindMapOffset, xd->tryMapOffset, xd->stateOffset);
                            auto tm = Rva2Ptr<TryMap>(xd->tryMapOffset);
                            if (tm != nullptr)
                            {
                                auto hm = Rva2Ptr<HandlerMap>(tm->handlerMapOffset);
                                for (unsigned int j = 0; j < tm->handlerMapCount; ++j)
                                {
                                    if (m_options.Verbose)
                                        printf("handler map %u: tdo %lx catch fn %lx\n", j, hm[j].typeDescriptorOffset, hm[j].catchFunctionOffset);
                                    m_dataToAdjust.insert(Rva(tm->handlerMapOffset + offsetof(HandlerMap, typeDescriptorOffset) + j * sizeof(HandlerMap)));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    std::string VecToString(const std::vector<Rva> &rvas)
    {
        if (rvas.empty())
            return std::string();

        std::stringstream result;

        result << std::hex << rvas[0].ToUL();

        for (size_t i = 1; i < rvas.size(); ++i)
            result << " " << rvas[i].ToUL();

        return result.str();
    }

    bool CheckForJumpToImport(const _CodeInfo &ci, Rva va, const _DInst dinst, BasicBlock *b)
    {
        if (dinst.opcode == I_JMP && (dinst.flags & FLAG_RIP_RELATIVE) != 0 && dinst.ops[0].type == O_SMEM)
        {
			Rva target = va + INSTRUCTION_GET_RIP_TARGET(&dinst);
            //auto it = m_vaToImportedSymbols.find(target);
            //if (it != m_vaToImportedSymbols.end())
            const char *symbol = m_importedDLLs.Find(target);
            if (symbol != nullptr)
            {
                b->label = std::string(symbol) + "*";
            }
        }

        return false;
    }

    Rva rdxValue;
    std::unordered_set<Rva> throwInfoObjects;

    bool CheckForThrowException(const _CodeInfo &ci, Rva va, const _DInst dinst, BasicBlock *b, Rva indirectThrowException)
    {
        if (dinst.opcode == I_LEA && dinst.ops[0].type == O_REG && dinst.ops[0].index == R_RDX && (dinst.flags & FLAG_RIP_RELATIVE) != 0 &&
            dinst.ops[1].type == O_SMEM)
        {
            rdxValue = va + INSTRUCTION_GET_RIP_TARGET(&dinst);
        }
        else if (dinst.opcode == I_XOR && dinst.ops[0].type == O_REG && dinst.ops[0].index == R_EDX && dinst.ops[1].type == O_REG && dinst.ops[1].index == dinst.ops[1].index)
        {
            rdxValue = Rva(0ul);
        }

        if (dinst.opcode == I_CALL)
        {
            if ((dinst.flags & FLAG_RIP_RELATIVE) != 0 && dinst.ops[0].type == O_SMEM)
            {
			    Rva target = va + INSTRUCTION_GET_RIP_TARGET(&dinst);
                if (target == indirectThrowException)
                {
                    if (rdxValue == Rva::Invalid())
                        printf("!!!! Expected rdx to be set!\n");
                    else if (rdxValue.ToUL() != 0)
                        throwInfoObjects.insert(rdxValue);
                }
            }
            else if (dinst.ops[0].type == O_PC)
            {
			    Rva target = va + INSTRUCTION_GET_TARGET(&dinst);
                if (target == indirectThrowException)
                {
                    if (rdxValue == Rva::Invalid())
                        printf("!!!! Expected rdx to be set! %lx\n", va.ToUL());
                    else if (rdxValue.ToUL() != 0)
                        throwInfoObjects.insert(rdxValue);
                }
            }
        }

        return true;
    }

    void DoDisassemble()
    {
        GatherAllTargets();

        for (auto v : m_dataToAdjust)
            printf("need to adjust %lx: %lx\n", v.ToUL(), *Rva2Ptr<unsigned int>(v));

        int textSection = FindSection(".text");
        if (textSection < 0)
        {
            printf("no text section\n");
            return;
        }

		DWORD textVa = m_sectionHeaders[textSection].VirtualAddress;
		DWORD textSize = m_sectionHeaders[textSection].SizeOfRawData;

        auto it = m_basicBlocks.begin();
        auto jt_it = m_basicBlocks.begin();

        while (it != m_basicBlocks.end())
        {
            BasicBlock *bb = *it;
            unsigned char *bbPtr = Rva2Ptr<unsigned char>(bb->start);
            if (bb->isJumpTable)
            {
                printf("-- jt %lx %lx - element size %d --\n", bb->start.ToUL(), bb->length, bb->jumpTableElementSize);
                for (unsigned int i = 0; i < bb->length / bb->jumpTableElementSize; ++i)
                {
                    if (bb->jumpTableElementSize == 1)
                    {
                        printf(" db %02x\n", 0xff & bbPtr[i]);
                    }
                    else if (bb->jumpTableElementSize == 2)
                    {
                        printf(" dw %04x\n", 0xffff & ((unsigned short *)bbPtr)[i]);
                    }
                    else if (bb->jumpTableElementSize == 4)
                    {
                        printf(" dl %lx\n", 0xffff & ((unsigned long *)bbPtr)[i]);
                    }
                }
            }
            else
            { 
                printf("-- bb %lx %lx -- succ '%s' pred '%s' -- %s %d-%d --\n", bb->start.ToUL(), bb->length, 
                    VecToString(bb->successors).c_str(), VecToString(bb->predecessors).c_str(),
                    bb->baseReg == R_NONE ? "" : (char *)GET_REGISTER_NAME(bb->baseReg), bb->baseRegSet, bb->baseRegClobbered);
			    Disassemble(bbPtr, bb->start, bb->length, [this](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->Printer(ci, va, dinst); });
            }
            auto nextIt = it;
            ++nextIt;
            if (nextIt != m_basicBlocks.end())
            {
                BasicBlock *nextBB = *nextIt;
                Rva nextStart = nextBB->start;

                Rva padStart = bb->start + bb->length;

                if (nextBB->isJumpTable && nextBB->jumpTableElementSize == 4)
                {
                    padStart = Rva((bb->start.ToUL() + bb->length + 3) & ~3);
                }

                Rva pad = padStart;
                while (pad < nextStart)
                {
                    BYTE b = *Rva2Ptr<BYTE>(pad);
                    if (b != 0xcc)
                    {
                        printf("%x: not all int 3! %x - %x - next %x\n", (bb->start + bb->length).ToUL(), padStart.ToUL(), pad.ToUL(), nextStart.ToUL());
                        pad = bb->start + bb->length;
                        while (pad < (*nextIt)->start)
                        {
                            printf("%02x", *Rva2Ptr<BYTE>(pad));
                            pad = pad + 1;
                        }
                        printf("\n");
                        break;
                    }
                    pad = pad + 1;
                }
            }

            it = nextIt;
        }
#if 0
		for (auto &t : m_targets)
			if (!t.second.defined && t.second.targetType != TargetType::DATA)
				printf("Target %d %lx %s not defined\n", t.second.label, t.first.ToUL(), ToString(t.second.targetType));
#endif
    }

    struct SECTION
    {
        IMAGE_SECTION_HEADER m_section;
        unsigned char *m_rawData;
    };

    void BuildSections(DWORD nSections, PIMAGE_SECTION_HEADER sectionHeaders)
    {
        for (DWORD i = 0; i < nSections; ++i)
        { 
            SECTION s;
            s.m_section = sectionHeaders[i];
            s.m_rawData = (unsigned char *)(m_base + s.m_section.PointerToRawData);
            m_sections.push_back(s);
        }
    }

    static bool IsExecutable(const IMAGE_SECTION_HEADER &s)
    {
        return (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }

    static bool IsWritable(const IMAGE_SECTION_HEADER &s)
    {
        return (s.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    void PrintSections()
    {
        printf("Base: %p => %p\n", m_base, m_base + m_originalLength);

		for (auto s : m_sections)
		{
			const IMAGE_SECTION_HEADER &head = s.m_section;
			printf("Section: %.8s va %x %x raw %x size %d, ptr %p => %p\n", 
                head.Name, head.VirtualAddress, head.Misc.VirtualSize, head.PointerToRawData, head.SizeOfRawData, s.m_rawData, s.m_rawData + head.SizeOfRawData);
			printf("  Line #s %x %d\n", head.PointerToLinenumbers, head.NumberOfLinenumbers);
			printf("  Relocs %x %d\n", head.PointerToRelocations, head.NumberOfRelocations);
			printf("  Char %x Misc %x\n", head.Characteristics, head.Misc.PhysicalAddress);
            char perms[32];
            char *p = perms;
            if ((head.Characteristics & IMAGE_SCN_MEM_READ) != 0)
                *p++ = 'R';
            if ((head.Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                *p++ = 'W';
            if ((head.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                *p++ = 'X';
            *p = '\0';
            if (strlen(perms) > 0)
                printf("  %s\n", perms);
		}
    }

    void PrintResourceDirectory(int level, char *resourceBase, IMAGE_RESOURCE_DIRECTORY *rsrc)
    {
        printf("Level %d Resource counts id %lx name %lx\n", level, rsrc->NumberOfIdEntries, rsrc->NumberOfNamedEntries);
        IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY *) (rsrc + 1);
        for (int i = 0; i < rsrc->NumberOfNamedEntries; ++i)
        {
            printf("name %lx %lx\n", entry->Name, entry->OffsetToData);
            ++entry;
        }
        for (int i = 0; i < rsrc->NumberOfIdEntries; ++i)
        {
            printf("id %lx off %lx\n", entry->Id, entry->OffsetToData);
            if (entry->DataIsDirectory)
            {
                IMAGE_RESOURCE_DIRECTORY *sub = (IMAGE_RESOURCE_DIRECTORY *)(resourceBase + entry->OffsetToDirectory);
                PrintResourceDirectory(level + 1, resourceBase, sub);
            }
            else
            {
                IMAGE_RESOURCE_DATA_ENTRY *data = (IMAGE_RESOURCE_DATA_ENTRY *)(resourceBase + entry->OffsetToData);
                printf("resource offset %lx\n", data->OffsetToData);
            }

            ++entry;
        }
    }

	void Process()
	{
		for (int i = 0; i < 16; ++i)
		{
			const IMAGE_DATA_DIRECTORY &data = m_optionalHeader->DataDirectory[i];
			printf(" %s Address %x Size %x %s\n", directoryNames[i], data.VirtualAddress, data.Size, data.VirtualAddress == 0 ? "" : (char *)Rva2Section(Rva(data.VirtualAddress))->Name);
		}

        PrintSections();

        if (m_options.Disassemble)
        {
            DoDisassemble();
        }

        if (m_options.PrintImports || m_options.PrintImportedDLLs)
        { 
            PrintImports();
            if (m_options.Verbose)
		        PrintIAT();
        }

        if (m_options.PrintExports)
        {
            PrintExports();
        }

        if (m_options.Verbose)
        {
            PrintLoadConfig();
            PrintTLS();

            if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0)
            {
                IMAGE_RESOURCE_DIRECTORY *rsrc = Rva2Ptr<IMAGE_RESOURCE_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
                if (m_options.Verbose)
                    PrintResourceDirectory(0, (char *)rsrc, rsrc);
            }

		    PrintRelocations();
            PrintFunctionTable();
        }
	}

    void PrintImports()
    {
        PrintDelayImports();
        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
            return;

	    printf("Imports at %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_IMPORT_DESCRIPTOR *descs = Rva2Ptr<IMAGE_IMPORT_DESCRIPTOR>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		IMAGE_IMPORT_DESCRIPTOR *desc = descs;
        DWORD off = 0;
		while (desc->Name != 0)
		{
			char *name = Rva2Ptr<char>(desc->Name);

            if (m_options.PrintImportedDLLs)
            {
                printf("%s\n", name);
            }
            else
            {
                printf("IID %x - orig %x ft %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + off, desc->OriginalFirstThunk, desc->FirstThunk);

                printf("Name %s, %s, forwarder %d, Original %lx => %lx, %s\n", name, Rva2Section(desc->Name)->Name, desc->ForwarderChain,
                    desc->OriginalFirstThunk, Rva2Offset(desc->OriginalFirstThunk), Rva2Section(desc->OriginalFirstThunk)->Name);

                if (desc->OriginalFirstThunk != 0 && m_options.Verbose)
                    PrintThunkData(Rva(desc->OriginalFirstThunk), Rva2Ptr<IMAGE_THUNK_DATA>(desc->OriginalFirstThunk));

                printf("IAT %lx => %lx, %s\n", desc->FirstThunk, Rva2Offset(desc->FirstThunk), Rva2Section(desc->FirstThunk)->Name);
                if (desc->FirstThunk != 0)
                    PrintThunkData(Rva(desc->FirstThunk), Rva2Ptr<IMAGE_THUNK_DATA>(desc->FirstThunk));
                printf("\n");
            }

			++desc;
            off+=sizeof(*desc);
		}
        printf("Directory end %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    }

    void PrintDelayImports()
    {
        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 0)
            return;

	    printf("DelayImports at %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
        IMAGE_DELAYLOAD_DESCRIPTOR *descs = Rva2Ptr<IMAGE_DELAYLOAD_DESCRIPTOR>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);

		IMAGE_DELAYLOAD_DESCRIPTOR *desc = descs;
		while (desc->DllNameRVA != 0)
		{
			char *name = Rva2Ptr<char>(desc->DllNameRVA);
            if (m_options.PrintImportedDLLs)                
                printf("%s\n", name);
            else
                printf("Name %s\n", name);
            if (desc->ImportNameTableRVA != 0 && m_options.PrintImports)
                PrintThunkData(Rva(desc->ImportNameTableRVA), Rva2Ptr<IMAGE_THUNK_DATA>(desc->ImportNameTableRVA));
            printf("iat %x module %x\n", desc->ImportAddressTableRVA, desc->ModuleHandleRVA);
            if (desc->ImportAddressTableRVA != 0 && m_options.PrintImports)
            {
                uint64_t *a = Rva2Ptr<uint64_t>(desc->ImportAddressTableRVA);
                for (int i = 0; a[i] != 0; ++i)
                    printf("%llx\n", a[i]);
            }

            ++desc;
		}
        printf("Directory end %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress + m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
    }

    void PrintFunctionTable()
    {
        int sectionNo = FindSection(".pdata");
        if (sectionNo < 0)
            return;
        DWORD nEntries = m_sections[sectionNo].m_section.SizeOfRawData / 12;
        RUNTIME_FUNCTION *entries = (RUNTIME_FUNCTION *)m_sections[sectionNo].m_rawData;
        for (DWORD i = 0; i < nEntries; ++i)
        {
            RUNTIME_FUNCTION &entry = entries[i];
            if (entry.BeginAddress == 0)
                break;
            BasicBlock *beginbb = FindBasicBlock(Rva(entry.BeginAddress));
            if (beginbb != nullptr)
                printf("begin %s\n", beginbb->GetLabel().c_str());
            printf("%08x %08x %08x\n", entry.BeginAddress, entry.EndAddress, entry.UnwindInfoAddress);
            auto s = Rva2Section(entry.UnwindInfoAddress);
            if (s != nullptr)
            {
                XData *xd = nullptr;
                auto ui = Rva2Ptr<UNWIND_INFO>(entry.UnwindInfoAddress);
                printf("DD %lx %u %u %s prolog %u # codes %u -- ", * (unsigned long *) ui, ui->Version, ui->Flags, ui->FlagString().c_str(), ui->SizeOfProlog, ui->CountOfCodes);
                if ((ui->Flags & UNW_FLAG_EHANDLER) != 0)
                {
                    printf(" ehandler %lx", ui->GetHandlerInfo().EHandler.ExceptionHandler);
                    BasicBlock *excbb = FindBasicBlock(Rva(ui->GetHandlerInfo().EHandler.ExceptionHandler));
                    if (excbb != nullptr)
                    { 
                        printf(" exc %s", excbb->GetLabel().c_str());
                        if (excbb->GetLabel() == "__CxxFrameHandler3*")
                        { 
                            printf(" data %lx", ui->GetHandlerInfo().EHandler.ExceptionHandlerData);
                            xd = Rva2Ptr<XData>(ui->GetHandlerInfo().EHandler.ExceptionHandlerData);
                        }
                    }
                }
                if ((ui->Flags & UNW_FLAG_CHAININFO) != 0)
                {
                    printf(" function %lx %lx %lx", ui->GetHandlerInfo().FunctionEntry.FunctionStartAddress, ui->GetHandlerInfo().FunctionEntry.FunctionEndAddress, ui->GetHandlerInfo().FunctionEntry.UnwindInfoAddress);
                }
                printf("\n");
                if (xd != nullptr)
                {
                    printf("xdata %lx %lx %lx %lx\n", xd->a, xd->unwindMapOffset, xd->tryMapOffset, xd->stateOffset);
                    auto um = Rva2Ptr<UnwindMap>(xd->unwindMapOffset);
                    if (um != nullptr)
                        printf("unwind destructor %lx\n", um->destructorOffset);
                    auto tm = Rva2Ptr<TryMap>(xd->tryMapOffset);
                    auto ip2 = Rva2Ptr<IP2Offset>(xd->stateOffset);
                    for (unsigned int j = 0; j < xd->stateCount; ++j)
                    {
                        printf("state %u: off %lx ?? %lx\n", j, ip2[j].functionOffset, ip2[j].b);
                    }

                    if (tm != nullptr)
                    { 
                        printf("try handler map %lx - count %u\n", tm->handlerMapOffset, tm->handlerMapCount);
                        auto hm = Rva2Ptr<HandlerMap>(tm->handlerMapOffset);
                        for (unsigned int j = 0; j < tm->handlerMapCount; ++j)
                        {
                            printf("handler map %u: tdo %lx catch fn %lx\n", j, hm[j].typeDescriptorOffset, hm[j].catchFunctionOffset);
                        }
                    }
                }
            }
        }
    }

    void AdjustResourceDirectory(char *resourceBase, IMAGE_RESOURCE_DIRECTORY *rsrc)
    {
        if (m_options.Verbose)
            printf("Resource counts id %lx name %lx\n", rsrc->NumberOfIdEntries, rsrc->NumberOfNamedEntries);
        IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY *) (rsrc + 1);
        for (int i = 0; i < rsrc->NumberOfNamedEntries; ++i)
        {
            printf("name %lx %lx\n", entry->Name, entry->OffsetToData);
            ++entry;
        }
        for (int i = 0; i < rsrc->NumberOfIdEntries; ++i)
        {
            if (m_options.Verbose)
                printf("id %lx off %lx\n", entry->Id, entry->OffsetToData);
            if (entry->DataIsDirectory)
            {
                IMAGE_RESOURCE_DIRECTORY *sub = (IMAGE_RESOURCE_DIRECTORY *)(resourceBase + entry->OffsetToDirectory);
                AdjustResourceDirectory(resourceBase, sub);
            }
            else
            {
                IMAGE_RESOURCE_DATA_ENTRY *data = (IMAGE_RESOURCE_DATA_ENTRY *)(resourceBase + entry->OffsetToData);
                if (m_options.Verbose)
                    printf("resource offset %lx\n", data->OffsetToData);
                AdjustRva(&data->OffsetToData);
            }

            ++entry;
        }
    }

    void AdjustRIPAddresses()
    {
        auto it = m_basicBlocks.begin();
        while (it != m_basicBlocks.end())
        {
            BasicBlock *bb = *it;
            //printf("-- bb %lx %lx --\n", bb->start.ToUL(), bb->length);
            if (!bb->isJumpTable)
            {
                m_lastInst.flags = FLAG_NOT_DECODABLE;

                Disassemble(Rva2Ptr<unsigned char>(bb->start), bb->start, bb->length, [this, bb](const _CodeInfo &ci, Rva va, const _DInst &dinst) 
                { 
                    this->AdjustRIPOperand(ci, va, dinst, bb); 
                    if (dinst.opcode == I_RET || dinst.opcode == I_JMP)
                    {
                        return false;
                    }
                    return true;
                });
            }
            ++it;
        }
    }

    struct Insertion
    {
        Rva vaInsert;
        DWORD vaDelta;
    };

    void MoveVa(Rva oldVa, DWORD size, Rva newVa)
    {
        Insertion after;
        after.vaInsert = oldVa + size;
        after.vaDelta = 0;
        m_insertions.insert(m_insertions.begin(), after);
        Insertion move;
        move.vaInsert = oldVa;
        move.vaDelta = newVa - oldVa;
        m_insertions.insert(m_insertions.begin(), move);

        for (auto i : m_insertions)
            printf("Insertion %x %d\n", i.vaInsert.ToUL(), i.vaDelta);
    }

    bool AdjustRva(Rva *rva)
    {
        auto it = m_replacementVas.find(*rva);
        if (it != m_replacementVas.end())
        {
            *rva = it->second;
            return true;
        }
        for (auto it = m_insertions.rbegin(); it != m_insertions.rend(); ++it)
        {
            if (*rva >= it->vaInsert)
            {
                if (it->vaDelta == 0)
                    return false;

                *rva += it->vaDelta;
                return true;
            }
        }

        return false;
    }

    bool AdjustRva(unsigned long *rva)
    {
        Rva t(*rva);
        if (AdjustRva(&t))
        {
            *rva = t.ToUL();
            return true;
        }
        return false;
    }

    bool AdjustVa(ULONGLONG *va)
    {
        unsigned long tmp = (unsigned long)(*va - m_imageBase);
        if (AdjustRva(&tmp))
        { 
            *va = m_newImageBase + tmp;
            return true;
        }

        if (m_newImageBase != m_imageBase)
        {
            *va = m_newImageBase + tmp;
            return true;
        }

        return false;
    }

    unsigned char *AddIINs(unsigned char *p, IMAGE_IMPORT_DESCRIPTOR *added, unsigned int nSymbols, const char *symbols[])
    {
        IMAGE_THUNK_DATA *itd = (IMAGE_THUNK_DATA *)p;
        memset(itd, 0, sizeof(IMAGE_THUNK_DATA) * (nSymbols + 1));
        p += (nSymbols + 1) * sizeof(IMAGE_THUNK_DATA);

        IMAGE_THUNK_DATA *of = itd;
        int hint = 1;
        for (unsigned int i = 0; i < nSymbols; ++i)
        {
            IMAGE_IMPORT_BY_NAME *iin = (IMAGE_IMPORT_BY_NAME *) p;
            iin->Hint = hint;
            ++hint;
            size_t len = strlen(symbols[i]);
            strcpy(iin->Name, symbols[i]);
            iin->Name[len++] = '\0';
            if ((len & 1) != 0)
                iin->Name[len++] = '\0';
            p += sizeof(WORD) + len;
            of->u1.AddressOfData = Ptr2Rva(iin).ToUL();
            ++of;
        }

        added->OriginalFirstThunk = Ptr2Rva(itd).ToUL();

        return p;
    }

    void AdjustSectionsAndDirectories(DWORD extra)
    {
        for (int i = 0; i < m_sections.size(); ++i)
        {
            if (AdjustRva(&m_sections[i].m_section.VirtualAddress))
            {
                m_sections[i].m_section.PointerToRawData += extra;
			    printf("Section %s Address %x Size %x\n", m_sections[i].m_section.Name, m_sections[i].m_section.VirtualAddress, m_sections[i].m_section.SizeOfRawData);
            }
        }

        for (int i = 0; i < 16; ++i)
		{
			IMAGE_DATA_DIRECTORY &data = m_optionalHeader->DataDirectory[i];

            if (AdjustRva(&data.VirtualAddress))
            {
			    printf("Offset %s Address %x Size %x\n", directoryNames[i], data.VirtualAddress, data.Size);
            }
		}
    }

    void PrintTLS()
    {
        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0)
        {
            IMAGE_TLS_DIRECTORY64 *tls = Rva2Ptr<IMAGE_TLS_DIRECTORY64>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
            printf("Start %llx\n", tls->StartAddressOfRawData);
            printf("End %llx\n", tls->EndAddressOfRawData);
            printf("Index %llx\n", tls->AddressOfIndex);
            printf("Callbacks %llx\n", tls->AddressOfCallBacks);
        }
    }

    void PrintLoadConfig()
    {
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size != 0)
        {
            printf("load config %zd\n", sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64));
            IMAGE_LOAD_CONFIG_DIRECTORY64 *config = Rva2Ptr<IMAGE_LOAD_CONFIG_DIRECTORY64>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
            printf("LockPrefixTable %llx\n", config->LockPrefixTable);
            printf("EditList %llx\n", config->EditList);
            //AdjustVa(&config->SecurityCookie);
            printf("SecurityCookie %llx\n", config->SecurityCookie);
            printf("SEHandlerTable %llx\n", config->SEHandlerTable);
            printf("GuardCFCheckFunctionPointer %llx\n", config->GuardCFCheckFunctionPointer);
            printf("GuardCFFunctionTable %llx\n", config->GuardCFFunctionTable);
        }
    }

    void AdjustExports()
    {
  		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
		{
			IMAGE_EXPORT_DIRECTORY *exports = Rva2Ptr<IMAGE_EXPORT_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			DWORD nameAddr = exports->AddressOfNames;
			DWORD *addressOfNames = Rva2Ptr<DWORD>(exports->AddressOfNames);
			DWORD *addressOfFunctions = Rva2Ptr<DWORD>(exports->AddressOfFunctions);
			for (unsigned int i = 0; i < exports->NumberOfNames; ++i)
			{
                Rva va(addressOfFunctions[i]);
                if (AdjustRva(&va))
                {
    				char *name = Rva2Ptr<char>(addressOfNames[i]);
                    if (m_options.Verbose)
                        printf("Adjusted export! %s %lx\n", name, va.ToUL());
                    addressOfFunctions[i] = va.ToUL();
                }
			}
		}

    }

    void ExtendImportData()
    {
        auto psection = Rva2Section(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        if (psection == nullptr)
            return;

        int section = FindSection((char *)psection->Name);

        if (section < 0)
        {
            printf("No rdata\n");
            return;
        }

        GatherAllTargets();

        printf("extending %d %s\n", section, (char *)m_sections[section].m_section.Name);
        SECTION &s = m_sections[section];

        AddImports(s);
        PrintLoadConfig();
        PrintTLS();

        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0)
        {
            IMAGE_RESOURCE_DIRECTORY *rsrc = Rva2Ptr<IMAGE_RESOURCE_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
            AdjustResourceDirectory((char *)rsrc, rsrc);
        }

        AdjustRIPAddresses();
        AdjustExports();

        for (auto v : m_dataToAdjust)
        {
            Rva t = v;
            AdjustRva(&t);
            Rva tt = Rva(*Rva2Ptr<unsigned long>(t));
            if (AdjustRva(&tt))
            {
                if (m_options.Verbose)
                    printf("adjusting %lx to %lx: %lx tp %lx\n", v.ToUL(), t.ToUL(), *Rva2Ptr<unsigned long>(t), tt.ToUL());
                *Rva2Ptr<unsigned long>(t) = tt.ToUL();
            }
        }
    }

	void AdjustThunkData(IMAGE_THUNK_DATA *thunkData)
	{
		while (thunkData->u1.AddressOfData != 0)
		{
            DWORD rva = (DWORD)thunkData->u1.AddressOfData;
            AdjustRva(&rva);
            thunkData->u1.AddressOfData = rva;

			IMAGE_IMPORT_BY_NAME *iin = Rva2Ptr<IMAGE_IMPORT_BY_NAME>(thunkData->u1.AddressOfData);
			printf("  %x %s - %s off %x %016llx\n", iin->Hint, iin->Name, Rva2Section((DWORD)thunkData->u1.AddressOfData)->Name, Rva2Offset((DWORD)thunkData->u1.AddressOfData), m_imageBase + thunkData->u1.AddressOfData);
			++thunkData;
		}
	}

    void AddImports(SECTION &s)
    {
        DWORD extra = 8192 + m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

        if ((extra & 4095) != 0)
            extra = (extra + 4096) & ~4095;

        unsigned char *newData = (unsigned char *)calloc(s.m_section.SizeOfRawData + extra, 1);
        printf("oldSize %d\n", s.m_section.SizeOfRawData);
        printf("newData %p %p\n", newData, newData + s.m_section.SizeOfRawData + extra);

        DWORD oldVaSize = (s.m_section.SizeOfRawData + 4095) & ~4095;
        DWORD newVaSize = (s.m_section.SizeOfRawData + extra + 4095) & ~4095;
        Insertion insert;
        insert.vaInsert = Rva(s.m_section.VirtualAddress + s.m_section.SizeOfRawData);
        insert.vaDelta = newVaSize - oldVaSize;
        printf("VA Insert %x VA delta %d\n", insert.vaInsert.ToUL(), insert.vaDelta);
        m_insertions.push_back(insert);
        memcpy(newData, s.m_rawData, s.m_section.SizeOfRawData);
        memset(newData + s.m_section.SizeOfRawData, '!', extra);

        unsigned char *inserted = newData + s.m_section.SizeOfRawData;

        s.m_rawData = newData;

        m_optionalHeader->SizeOfInitializedData += m_insertions.back().vaDelta;
        m_optionalHeader->SizeOfImage += m_insertions.back().vaDelta;

        OffsetRelocations();

        s.m_section.SizeOfRawData += extra;
        s.m_section.Misc.VirtualSize += extra;

        AdjustSectionsAndDirectories(extra);

        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
		{
			IMAGE_IMPORT_DESCRIPTOR *descs = Rva2Ptr<IMAGE_IMPORT_DESCRIPTOR>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			IMAGE_IMPORT_DESCRIPTOR *desc = descs;
            unsigned int descCount = 0;
			while (desc->Name != 0)
			{
                ++descCount;
                ++desc;
            }

            printf("descCount %d size %zd\n", descCount, descCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));

            IMAGE_IMPORT_DESCRIPTOR *newDescs = (IMAGE_IMPORT_DESCRIPTOR *) inserted;
            memcpy(newDescs, descs, descCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            IMAGE_IMPORT_DESCRIPTOR *added = newDescs + descCount;
            memset(added, 0, 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR));

            m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = insert.vaInsert.ToUL();
            m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (descCount + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

            unsigned char *p = (unsigned char *)(added + 2);
            const char *dll = "watch-de-memory.dll";
            strcpy(reinterpret_cast<char *>(p), dll);
            added->Name = Ptr2Rva(p).ToUL();
            p += strlen(dll);
            if (((uintptr_t)p & 7) != 0)
                p += 8 - ((uintptr_t)p & 7);
            const char *symbols[] = 
            { 
                "calloc", 
                "malloc", 
                "free", 
                "realloc", 
                "HeapAlloc", 
                "HeapFree", 
                "HeapReAlloc", 
                "HeapSize",
                "InitializeCriticalSection",
                "InitializeCriticalSectionAndSpinCount",
                "EnterCriticalSection",
                "LeaveCriticalSection",
                "DeleteCriticalSection"
            };
            const char *replacement_symbols[] = 
            { 
                "wdm_calloc", 
                "wdm_malloc", 
                "wdm_free", 
                "wdm_realloc", 
                "wdm_HeapAlloc", 
                "wdm_HeapFree", 
                "wdm_HeapReAlloc", 
                "wdm_HeapSize",
                "wdm_InitializeCriticalSection",
                "wdm_InitializeCriticalSectionAndSpinCount",
                "wdm_EnterCriticalSection",
                "wdm_LeaveCriticalSection",
                "wdm_DeleteCriticalSection"
            };
            unsigned int nSymbols = sizeof(symbols) / sizeof(symbols[0]);
            p = AddIINs(p, added, nSymbols, replacement_symbols);


            IMAGE_THUNK_DATA *newIat = (IMAGE_THUNK_DATA *)p;
            DWORD oldVa = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            DWORD oldSize = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
            printf("added %x import orig %x - oldSize %lu\n", Ptr2Rva(added).ToUL(), added->OriginalFirstThunk, oldSize);
            printf("%p %p\n", newIat, Rva2Ptr<char *>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
            printf("tops %p %p\n", newIat + oldSize, Rva2Ptr<char *>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) + oldSize);
            memcpy(newIat, Rva2Ptr<char *>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), oldSize);
            m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = Ptr2Rva(newIat).ToUL();
            for (unsigned int i = 0; i < descCount; ++i)
                newDescs[i].FirstThunk += Ptr2Rva(newIat).ToUL() - oldVa;
            m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size += (nSymbols + 1) * sizeof(IMAGE_THUNK_DATA);
            p +=  m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

            if (Ptr2Rva(p) >= m_insertions.back().vaInsert + m_insertions.back().vaDelta)
                throw "OVERFLOW of insertion";

            IMAGE_THUNK_DATA *f = newIat + (oldSize / sizeof(IMAGE_THUNK_DATA));
            added->FirstThunk = Ptr2Rva(f).ToUL();

            IMAGE_THUNK_DATA *of = Rva2Ptr<IMAGE_THUNK_DATA>(added->OriginalFirstThunk);
            Rva replacement(added->FirstThunk);
            for (unsigned int i = 0; i < nSymbols; ++i)
            {
                f->u1.AddressOfData = of->u1.AddressOfData;
                Rva origVa = m_importedDLLs.Find(symbols[i]);
                if (!origVa.IsZero())
                {
                    m_replacementVas.insert(std::make_pair(origVa, replacement));
                }
#if 0
                auto it = m_importedSymbols.find(symbols[i]);
                if (it != m_importedSymbols.end())
                {
                    m_replacementVas.insert(std::make_pair(it->second, replacement));
                }
#endif
                replacement += sizeof(IMAGE_THUNK_DATA);
                ++f;
                ++of;
            }
            f->u1.AddressOfData = 0;

            MoveVa(Rva(oldVa), oldSize, Ptr2Rva(newIat));
            printf("added %x import orig %x ft %x\n", Ptr2Rva(added).ToUL(), added->OriginalFirstThunk, added->FirstThunk);
        }
    }

    void Edit()
    {
        ExtendImportData();
        if (m_options.FixedAddress)
        {
            m_optionalHeader->DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            m_optionalHeader->ImageBase = 0x500000000;
        }
    }

	void PrintIAT()
	{
        DWORD size = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
		if (size != 0)
		{
            DWORD64 *entries = Rva2Ptr<DWORD64>(Rva(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
            DWORD nEntries = size / sizeof(*entries);
			printf("IAT dir %x size %d nEntries %lu\n", Rva2Offset(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), size, nEntries);
            for (unsigned int i = 0; i < nEntries; ++i)
            {
                DWORD64 e = entries[i];
                if (e != 0)
                {
                    if (!GetTopBit(e))
                    {
                        IMAGE_IMPORT_BY_NAME *iin = Rva2Ptr<IMAGE_IMPORT_BY_NAME>(Rva(e));
                        if (iin == nullptr)
                            printf("bad iin\n");
                        else
                            printf("%llx %s\n", e, iin->Name);
                    }
                    else
                    {
                        printf("Ordinal: %llx\n", ClearTopBit(e));
                    }
                }
            }
		}
	}

	void PrintRelocations()
	{
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
		{
			IMAGE_BASE_RELOCATION *reloc = Rva2Ptr<IMAGE_BASE_RELOCATION>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			DWORD sizeLeft = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			while (sizeLeft > 0)
			{
				printf("Reloc size %x va %x, %s\n", reloc->SizeOfBlock, reloc->VirtualAddress, Rva2Section(reloc->VirtualAddress)->Name);
                if (reloc->SizeOfBlock == 0)
                {
                    printf("bad reloc!\n");
                    return;
                }
				sizeLeft -= reloc->SizeOfBlock;
                WORD *r = (WORD *)(reloc + 1);
                int nRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (int i = 0; i < nRelocs; ++i)
                {
                    unsigned int relType = r[i] >> 12;
                    unsigned int relOffset = r[i] & 0xfff;
                    if (relType == 0)
                        continue;
                    if (relType == IMAGE_REL_BASED_DIR64)
                    {
                        uint64_t va = *Rva2Ptr<uint64_t>(reloc->VirtualAddress + relOffset);
                        printf("dir64 %x %llx\n", reloc->VirtualAddress + relOffset, *Rva2Ptr<uint64_t>(reloc->VirtualAddress + relOffset));
                    }
                    else
                        printf("reltype %d!\n", relType);
                }

				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<char *>(reloc) + reloc->SizeOfBlock);
			}
		}
	}

	void OffsetRelocations()
	{
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0)
		{
			IMAGE_BASE_RELOCATION *reloc = Rva2Ptr<IMAGE_BASE_RELOCATION>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			DWORD sizeLeft = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            printf("OffsetRelocations %d\n", sizeLeft);
			while (sizeLeft > 0)
			{
                WORD *r = (WORD *)(reloc + 1);
                int nRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (int i = 0; i < nRelocs; ++i)
                {
                    unsigned int relType = r[i] >> 12;
                    unsigned int relOffset = r[i] & 0xfff;
                    if (relType == 0)
                        continue;
                    if (relType == IMAGE_REL_BASED_DIR64)
                    {
                        uint64_t &addr = *Rva2Ptr<uint64_t>(reloc->VirtualAddress + relOffset);

                        Rva rva(addr - m_imageBase);
                        //printf("inspect address %llx\n", addr);
                        if (AdjustRva(&rva) || m_imageBase != m_newImageBase)
                        { 
                            addr = rva.ToUL() + m_newImageBase;
                            //printf("adjusted dir64 %lx %llx\n", reloc->VirtualAddress + relOffset, addr);
                        }
                    }
                    else
                        printf("bad reltype %d\n", relType);
                }

                if (AdjustRva(&reloc->VirtualAddress))
                {
				    printf("Offset Reloc size %x va %x\n", reloc->SizeOfBlock, reloc->VirtualAddress);
                }
				sizeLeft -= reloc->SizeOfBlock;
				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<char *>(reloc) + reloc->SizeOfBlock);
			}
		}
	}

private:
    std::set<BasicBlock *, BlockStartLess> m_basicBlocks;
    std::map<Rva, TargetInfo> m_targets;
    std::set<Rva> m_relocations;
    std::set<Rva> m_dataToAdjust;

	unsigned char *m_base;
	off_t m_originalLength;
	int m_nSections;
	IMAGE_SECTION_HEADER *m_sectionHeaders;
    std::vector<SECTION> m_sections;
	IMAGE_OPTIONAL_HEADER64 *m_optionalHeader;
	ULONGLONG m_imageBase;
	ULONGLONG m_newImageBase;
    _DInst m_lastInst;
    int m_lastOperandOffset;
    std::vector<Insertion> m_insertions;
    std::unordered_map<Rva, Rva> m_replacementVas;
	//std::unordered_map<Rva, std::string> m_vaToImportedSymbols;
	//std::unordered_map<std::string, Rva> m_importedSymbols;
    ImportedDLLs m_importedDLLs;
	std::unordered_map<Rva, std::string> m_exportedSymbols;
    Options m_options;
};

int main(int argc, char *argv[])
{
    Options options;
    std::vector<const char *> filenames;
    const char *out_filename = nullptr;
    const char *out_directory = nullptr;

    ConfigFile f("test.toml");
    f.Load();

    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-')
        {
            if (strcmp(argv[i], "-dis") == 0)
                options.Disassemble = true;
            else if (strcmp(argv[i], "-edit") == 0)
                options.Edit = true;
            else if (strcmp(argv[i], "-v") == 0)
                options.Verbose = true;
            else if (strcmp(argv[i], "-imports") == 0)
                options.PrintImports = true;
            else if (strcmp(argv[i], "-exports") == 0)
                options.PrintExports = true;
            else if (strcmp(argv[i], "-imported_dlls") == 0)
                options.PrintImportedDLLs = true;
            else if (strcmp(argv[i], "-fix") == 0)
                options.FixedAddress = true;
            else if (strcmp(argv[i], "-out") == 0)
            {
                if (i < argc - 1)
                {
                    out_filename = argv[i + 1];
                    ++i;
                }
            }
            else if (strcmp(argv[i], "-outd") == 0)
            {
                if (i < argc - 1)
                {
                    out_directory = argv[i + 1];
                    ++i;
                }
            }
            else
            {
                fprintf(stderr, "unrecognised command line switch: %s\n", argv[i]);
            }
        }
        else
        {
            filenames.push_back(argv[i]);
        }
    }

    if (options.Verbose)
        options.PrintImports = true;

    if (options.Edit && (out_filename == nullptr && out_directory == nullptr))
    {
        fprintf(stderr, "expect -out <filename> or -outd <directory>\n");
        exit(EXIT_FAILURE);
    }

    bool failed = false;
    for (auto filename : filenames)
    { 
        try
        { 
            PEFile file(filename, options);

            if (options.Edit)
            {
                std::string output = out_filename != nullptr ? out_filename : "";

                if (out_directory != nullptr)
                {
                    std::string f = filename;
                    output = out_directory;
                    output += '\\';

                    auto bs = f.find_last_of('\\');
                    auto fs = f.find_last_of('/', bs);

                    std::string::size_type d = fs != std::string::npos ? fs : bs;

                    if (d != std::string::npos)
                        output += f.substr(d + 1);
                    else
                        output += f;
                }

                printf("output %s\n", output.c_str());

                file.Edit();

                if (!file.Write(output.c_str()))
                    fprintf(stderr, "Failed to write to: %s\n", output.c_str());
            }
            else
            { 
	            file.Process();
            }
            printf("OK\n");
        }
        catch (const char *e)
        {
            fprintf(stderr, "oh dear: %s\n", e);
            failed = true;
        }
    }

    if (failed)
        exit(EXIT_FAILURE);

    return 0;
}

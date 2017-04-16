#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <distorm.h>
#include <algorithm>
#include <functional>
#include <map>
#include <mnemonics.h>
#include <set>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rva.h"
#include "unwind.h"

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
	PEFile(const char *filename)
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
		printf("length %d x%x\n", (int)m_originalLength, (int)m_originalLength);
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

	void ProcessThunkData(Rva va, IMAGE_THUNK_DATA *thunkData)
	{
        if (thunkData->u1.AddressOfData == 0)
            printf("Empty thunks\n");
		while (thunkData->u1.AddressOfData != 0)
		{
            bool isOrdinal = GetTopBit(thunkData->u1.AddressOfData);

            if (isOrdinal)
            {
                printf("Ordinal: %llu\n", ClearTopBit(thunkData->u1.AddressOfData));
            }
            else
            {
			    IMAGE_IMPORT_BY_NAME *iin = Rva2Ptr<IMAGE_IMPORT_BY_NAME>(Rva(thunkData->u1.AddressOfData));
                if (iin == nullptr)
                {
                    printf("bad iin!\n");
                    return;
                }
			    printf("%lx iin va %lx to %lx - %x %s - %s off %x\n", va.ToUL(), (DWORD)thunkData->u1.AddressOfData, 
                    ((DWORD)thunkData->u1.AddressOfData + (DWORD)sizeof(IMAGE_IMPORT_BY_NAME) + (DWORD)strlen(iin->Name) + 1) & ~1,
                    iin->Hint, iin->Name, Rva2Section(Rva(thunkData->u1.AddressOfData))->Name, Rva2Offset(Rva(thunkData->u1.AddressOfData)));
            }
			++thunkData;
            va += sizeof(*thunkData);
		}
	}

	std::unordered_map<Rva, std::string> m_vaToImportedSymbols;
	std::unordered_map<std::string, Rva> m_importedSymbols;
	std::unordered_map<Rva, std::string> m_exportedSymbols;

	void GatherImportedSymbols(Rva va, IMAGE_THUNK_DATA *thunkData)
	{
		while (thunkData->u1.AddressOfData != 0)
		{
           bool isOrdinal = GetTopBit(thunkData->u1.AddressOfData);

            if (isOrdinal)
            {
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "Ordinal %llu", ClearTopBit(thunkData->u1.AddressOfData));
                char *n = _strdup(tmp);
    			//printf("Imported %016llx %s\n", m_imageBase + va, n);
			    m_vaToImportedSymbols.insert(std::make_pair(va, n));
                m_importedSymbols.insert(std::make_pair(n, va));
            }
            else
            {
                IMAGE_IMPORT_BY_NAME *iin = Rva2Ptr<IMAGE_IMPORT_BY_NAME>(thunkData->u1.AddressOfData);
                if (iin == nullptr)
                {
                    printf("bad iin!\n");
                    return;
                }
			    m_vaToImportedSymbols.insert(std::make_pair(va, iin->Name));
                m_importedSymbols.insert(std::make_pair(iin->Name, va));
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
				GatherImportedSymbols(Rva(desc->FirstThunk), Rva2Ptr<IMAGE_THUNK_DATA>(desc->FirstThunk));
				++desc;
			}
		}
	}

	void GatherExportedSymbols()
	{
		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
		{
			IMAGE_EXPORT_DIRECTORY *exports = Rva2Ptr<IMAGE_EXPORT_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			DWORD nameAddr = exports->AddressOfNames;
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
            m_targets.insert(std::make_pair(entry.BeginAddress, TargetInfo(TargetType::FUNCTION, true)));
        }
    }

	typedef std::function<bool(const _CodeInfo &ci, Rva va, const _DInst &dinst)> InstructionHandler;

    enum class TargetType
    {
        FUNCTION,
        CFUNCTION,
        RFUNCTION,
        LABEL,
        ENTRY,
        DATA
    };

	struct TargetInfo
	{
		explicit TargetInfo(TargetType t) : label(0), targetType(t), defined(false)
		{
		}
		explicit TargetInfo(TargetType t, bool d) : label(0), targetType(t), defined(d)
		{
		}
		unsigned int label;
        TargetType targetType;
		bool defined;
	};

	std::map<Rva, TargetInfo> m_targets;
	std::set<Rva> m_newTargets;
    std::set<Rva> m_processedTargets;
    unsigned long m_bbSize;

	bool GatherNewTargets(const _CodeInfo &ci, Rva va, const _DInst dinst)
	{
		Rva a = va + dinst.addr;

        m_processedTargets.insert(a);
        m_bbSize += dinst.size;

		for (int j = 0; j < OPERANDS_NO; ++j)
		{
			if (dinst.ops[j].type == O_NONE)
				break;
			Rva target = Rva::Invalid();
			TargetType type = dinst.opcode == I_CALL ? TargetType::CFUNCTION : TargetType::LABEL;

			if (dinst.ops[j].type == O_PC)
			{
				target = va + INSTRUCTION_GET_TARGET(&dinst);
			}
			if (dinst.ops[j].type == O_SMEM && (dinst.flags & FLAG_RIP_RELATIVE) != 0)
			{
				target = va + INSTRUCTION_GET_RIP_TARGET(&dinst);
			}

            if (target != Rva::Invalid())
            { 
			    auto it = m_targets.find(target);
			    if (it == m_targets.end() && m_vaToImportedSymbols.count(target) == 0)
			    {
                    auto s = Rva2Section(target);
                    if (s != nullptr && !IsExecutable(*s))
                        type = TargetType::DATA;
                        
				    m_targets.insert(std::make_pair(target, TargetInfo(type)));
                    m_newTargets.insert(target);
			    }
			    else if (it != m_targets.end() && type == TargetType::CFUNCTION && it->second.targetType != TargetType::FUNCTION)
				    it->second.targetType = type;
            }
		}

        return dinst.opcode != I_JMP && dinst.opcode != I_RET;
	}

    bool m_haveLabels = false;

	void AssignLabels()
	{
        m_haveLabels = true;
		unsigned int lab = 0;
		for (auto &tpair : m_targets)
			tpair.second.label = ++lab;
	}

    struct BBState
    {
        int m_baseReg = R_NONE;
    };

	void AdjustRIPOperand(const _CodeInfo &ci, Rva va, const _DInst dinst, BBState &state)
    {
        if ((dinst.flags & FLAG_DST_WR) != 0 && dinst.ops[0].type == O_REG && dinst.ops[0].index == state.m_baseReg)
        { 
            printf("Clobber!\n");
            Printer(ci, va, dinst);
            state.m_baseReg = R_NONE;
        }
        int operandOffset = dinst.size;
        int opSize = 4;
        int skippedOp = 128;
        bool pcRel = false;
        bool adjustDisp = false;
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
            else if (dinst.ops[j].type == O_REG)
            {
            }
            else if (dinst.ops[j].type == O_MEM)
            {
                if (dinst.base != R_NONE && dinst.base == state.m_baseReg)
                {
                    printf("using base! %llu\n", dinst.disp);
                    Rva b = Rva(dinst.disp);
                    Printer(ci, va, dinst);
                    if (AdjustRva(&b))
                    {
                        printf("needs adjust!\n");
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

        if (operandOffset == dinst.size && !adjustDisp)
            return;

        Rva targetVa = va + (pcRel ? INSTRUCTION_GET_TARGET(&dinst) : INSTRUCTION_GET_RIP_TARGET(&dinst));
        Rva oldTargetVa = targetVa;

        if (opSize != 4 && !adjustDisp)
        {
            if (AdjustRva(&targetVa))
                printf("can not handle op off %d/%d size %d at %x - %d\n", operandOffset, dinst.size, opSize, (DWORD)(va.ToUL() + dinst.addr), pcRel);
            return;
        }

        if (dinst.opcode == I_LEA && (dinst.flags & FLAG_RIP_RELATIVE) != 0)
        {
            if (targetVa.ToUL() == 0)
            {
                state.m_baseReg = dinst.ops[0].index;
                printf("LEA RIP! %s\n", GET_REGISTER_NAME(state.m_baseReg));
                Printer(ci, va, dinst);
            }
        }


        if (adjustDisp)
        {
			printf("Instr at %lx: Adjust disp\n", (va + dinst.addr).ToUL());
            DWORD *dispLoc = Rva2Ptr<DWORD>((va + dinst.addr).ToUL() + operandOffset);
            unsigned long newDisp = (unsigned long)dinst.disp;
            AdjustRva(&newDisp);
            memcpy(dispLoc, &newDisp, 4);
            _DInst tmp(dinst);
            tmp.disp = newDisp;
            Printer(ci, va, tmp);
        }
        else if (AdjustRva(&targetVa))
        {
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
                Printer(ci, va, tmp);
            }
        }
    }

    static const char *ToString(TargetType type)
    {
        switch (type)
        {
        case TargetType::FUNCTION:
            return "fn";
        case TargetType::CFUNCTION:
            return "cfn";
        case TargetType::RFUNCTION:
            return "rfn";
        case TargetType::LABEL:
            return "lab";
        case TargetType::ENTRY:
            return "entry";
        case TargetType::DATA:
            return "dat";
        default:
            return "???";
        }
    }

    unsigned long long ToVa(Rva r)
    {
        return m_imageBase + r.ToUL();
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

        if (m_haveLabels)
        {
            auto it = m_targets.find(a);
		    if (it != m_targets.end())
		    {
			    printf("%s%u:\n", ToString(it->second.targetType), it->second.label);
			    it->second.defined = true;
		    }
        }

		auto it2 = m_exportedSymbols.find(a);
		if (it2 != m_exportedSymbols.end())
			printf("%s:\n", it2->second.c_str());

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
                if (m_haveLabels)
                {
				    auto it = m_targets.find(target);
				    if (it != m_targets.end())
					    printf(" %s%u.", ToString(it->second.targetType), it->second.label);
                }

				auto importIt = m_vaToImportedSymbols.find(target);
				if (importIt != m_vaToImportedSymbols.end())
					printf(" %s", importIt->second.c_str());
			}
		}
		printf("\n");

        return dinst.opcode != I_JMP && dinst.opcode != I_RET;
	}

	void Disassemble(Rva va, DWORD size, InstructionHandler handler)
	{
		const int MAX_INSTRUCTIONS = 1000;
	
		unsigned char *buf = Rva2Ptr<unsigned char>(va);
		_OffsetType offset = 0;

		for (;;)
		{
			// Decoded instruction information.
			_DInst decomposedInstructions[MAX_INSTRUCTIONS];
			// next is used for instruction's offset synchronization.
			// decodedInstructionsCount holds the count of filled instructions' array by the decoder.
			unsigned int decodedInstructionsCount = 0;

			// Default decoding mode is 32 bits, could be			// If you get an unresolved external symbol linker error for the following line,
			// change the SUPPORT_64BIT_OFFSET in distorm.h.
			_CodeInfo ci;
			ci.code = buf;
			ci.codeLen = size;
			ci.codeOffset = offset;
			ci.dt = Decode64Bits;
			ci.features = DF_NONE;
			_DecodeResult res = distorm_decompose(&ci, decomposedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
			if (res == DECRES_INPUTERR) 
			{
				// Null buffer? Decode type not 16/32/64?
				printf("Input error, halting!\n");
				break;
			}

            bool stop = false;
			for (unsigned int i = 0; i < decodedInstructionsCount; i++) 
			{
				if (!handler(ci, va, decomposedInstructions[i]))
                {
                    stop = true;
                    break;
                }
			}

            if (stop)
                break;

			if (res == DECRES_SUCCESS) 
				break; // All instructions were decoded.
			else if (decodedInstructionsCount == 0) 
				break;

			buf += ci.nextOffset - offset;
			size -= (DWORD)(ci.nextOffset - offset);
			offset = ci.nextOffset;
		}
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

		m_optionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 *>(fileHeader + 1);

		printf("Machine %x\n", fileHeader->Machine);
		printf("# sections %d\n", fileHeader->NumberOfSections);
		printf("sym tab %d\n", fileHeader->PointerToSymbolTable);
		printf("load address %llx\n", m_optionalHeader->ImageBase);
		m_imageBase = m_optionalHeader->ImageBase;
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

    struct BasicBlock
    {
        static int nextId;

        BasicBlock(Rva s, unsigned long l) : id(++nextId), start(s), length(l)
        {
        }
        BasicBlock(Rva s) : id(0), start(s), length(0)
        {
        }
        unsigned int id;
        Rva start;
        unsigned long length;
    };

    struct BlockStartLess
    {
        bool operator() (const BasicBlock *a, const BasicBlock *b) const
        {
            return a->start < b->start;
        }
    };

    std::set<BasicBlock *, BlockStartLess> m_basicBlocks;

    void GatherAllTargets()
    {
        int textSection = FindSection(".text");
        if (textSection < 0)
        {
            printf("no text section\n");
            return;
        }
		DWORD textVa = m_sectionHeaders[textSection].VirtualAddress;
		DWORD textSize = m_sectionHeaders[textSection].SizeOfRawData;

        m_targets.clear();
        if (!m_basicBlocks.empty())
            printf("Need to free!\n");
        m_basicBlocks.clear();

		GatherImportedSymbols();

		GatherExportedSymbols();

        if (m_optionalHeader->AddressOfEntryPoint != 0)
        {
            m_targets.insert(std::make_pair(m_optionalHeader->AddressOfEntryPoint, TargetInfo(TargetType::ENTRY)));
        }

        GatherFunctionTable();
        GatherRelocationTargets();

		if (textVa != 0)
		{
            std::set<Rva> unprocessedTargets;

            for (const auto &e : m_targets)
            { 
                unprocessedTargets.insert(e.first); 
            }

            for (const auto &e : m_exportedSymbols)
            {
                unprocessedTargets.insert(e.first); 
            }

            while (!unprocessedTargets.empty())
            {
                Rva rva = *unprocessedTargets.begin();

                auto s = Rva2Section(rva);
                if (!IsExecutable(*s))
                {
                    //printf("not exec! %lx\n", rva.ToUL());
                    unprocessedTargets.erase(rva);
                    continue;
                }

                //printf("start at %lx\n", rva.ToUL());
                m_processedTargets.clear();
                m_newTargets.clear();

                m_bbSize = 0;

                Disassemble(rva, textSize, [this](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->GatherNewTargets(ci, va, dinst); });

                auto b = new BasicBlock(rva, m_bbSize);

                m_basicBlocks.insert(b);

                for (Rva target : m_processedTargets)
                {
                    //printf("Processsed %x\n", target.ToUL());
                    m_newTargets.erase(target);
                    unprocessedTargets.erase(target);
                    if (rva != target)
                    {
                        BasicBlock tmp(target);
                        m_basicBlocks.erase(&tmp);
                    }
                }

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
                                alreadyProcessed = true;
                        }
                        else
                            printf("refound first BB!\n");
                        // TODO do the special cases
                    }

                    if (!alreadyProcessed)
                        unprocessedTargets.insert(target);
                }
            }
        }
    }

    void Disassemble()
    {
        GatherAllTargets();

		AssignLabels();

        int textSection = FindSection(".text");
        if (textSection < 0)
        {
            printf("no text section\n");
            return;
        }
		DWORD textVa = m_sectionHeaders[textSection].VirtualAddress;
		DWORD textSize = m_sectionHeaders[textSection].SizeOfRawData;

        auto it = m_basicBlocks.begin();
        while (it != m_basicBlocks.end())
        {
            BasicBlock *bb = *it;
            printf("-- bb %lx %lx --\n", bb->start.ToUL(), bb->length);
			Disassemble(bb->start, bb->length, [this](const _CodeInfo &ci, Rva va, const _DInst &dinst) { return this->Printer(ci, va, dinst); });
            auto nextIt = it;
            ++nextIt;
            if (nextIt != m_basicBlocks.end())
            {
                Rva pad = bb->start + bb->length;
                while (pad < (*nextIt)->start)
                {
                    if (*Rva2Ptr<BYTE>(pad) != 0xcc)
                    {
                        pad = bb->start + bb->length;
                        printf("%x: not all int 3!\n", pad.ToUL());
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

		for (auto &t : m_targets)
			if (!t.second.defined && t.second.targetType != TargetType::DATA)
				printf("Target %d %lx %s not defined\n", t.second.label, t.first.ToUL(), ToString(t.second.targetType));
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

    void DumpResourceDirectory(int level, char *resourceBase, IMAGE_RESOURCE_DIRECTORY *rsrc)
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
                DumpResourceDirectory(level + 1, resourceBase, sub);
            }
            else
            {
                IMAGE_RESOURCE_DATA_ENTRY *data = (IMAGE_RESOURCE_DATA_ENTRY *)(resourceBase + entry->OffsetToData);
                printf("resource offset %lx\n", data->OffsetToData);
            }

            ++entry;
        }
    }

	void Process(bool disassem, bool verbose)
	{
		for (int i = 0; i < 16; ++i)
		{
			const IMAGE_DATA_DIRECTORY &data = m_optionalHeader->DataDirectory[i];
			printf(" %s Address %x Size %x %s\n", directoryNames[i], data.VirtualAddress, data.Size, data.VirtualAddress == 0 ? "" : (char *)Rva2Section(Rva(data.VirtualAddress))->Name);
		}

        PrintSections();

        if (disassem)
        {
            Disassemble();
        }

        if (!disassem || verbose)
        {
		    if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size != 0)
            {
                printf("load config %zd\n", sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64));
                IMAGE_LOAD_CONFIG_DIRECTORY64 *config = Rva2Ptr<IMAGE_LOAD_CONFIG_DIRECTORY64>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
                printf("LockPrefixTable %llx\n", config->LockPrefixTable);
                printf("EditList %llx\n", config->EditList);
                printf("SecurityCookie %llx\n", config->SecurityCookie);
                printf("SEHandlerTable %llx\n", config->SEHandlerTable);
                printf("GuardCFCheckFunctionPointer %llx\n", config->GuardCFCheckFunctionPointer);
                printf("GuardCFFunctionTable %llx\n", config->GuardCFFunctionTable);
            }

            if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0)
            {
                IMAGE_TLS_DIRECTORY64 *tls = Rva2Ptr<IMAGE_TLS_DIRECTORY64>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                printf("Start %llx\n", tls->StartAddressOfRawData);
                printf("End %llx\n", tls->EndAddressOfRawData);
                printf("Index %llx\n", tls->AddressOfIndex);
                printf("Callbacks %llx\n", tls->AddressOfCallBacks);
            }
            if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0)
            {
                IMAGE_RESOURCE_DIRECTORY *rsrc = Rva2Ptr<IMAGE_RESOURCE_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
                DumpResourceDirectory(0, (char *)rsrc, rsrc);
            }
            if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
		    {
                printf("Imports at %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
                IMAGE_IMPORT_DESCRIPTOR *descs = Rva2Ptr<IMAGE_IMPORT_DESCRIPTOR>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			    IMAGE_IMPORT_DESCRIPTOR *desc = descs;
                DWORD off = 0;
			    while (desc->Name != 0)
			    {
                    printf("IID %x - orif %x ft %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + off, desc->OriginalFirstThunk, desc->FirstThunk);
				    char *name = Rva2Ptr<char>(desc->Name);
                    printf("Name RVA %x to %x\n", desc->Name, (desc->Name + (DWORD)strlen(name) + 2) & ~1);

				    printf("Name %s, %s, forwarder %d\n", name, Rva2Section(desc->Name)->Name, desc->ForwarderChain);

				    printf("Original %lx => %lx, %s\n", desc->OriginalFirstThunk, Rva2Offset(desc->OriginalFirstThunk), Rva2Section(desc->OriginalFirstThunk)->Name);
                    if (desc->OriginalFirstThunk != 0)
				        ProcessThunkData(Rva(desc->OriginalFirstThunk), Rva2Ptr<IMAGE_THUNK_DATA>(desc->OriginalFirstThunk));
				    printf("IAT %lx => %lx, %s\n", desc->FirstThunk, Rva2Offset(desc->FirstThunk), Rva2Section(desc->FirstThunk)->Name);
                    if (desc->FirstThunk != 0)
				        ProcessThunkData(Rva(desc->FirstThunk), Rva2Ptr<IMAGE_THUNK_DATA>(desc->FirstThunk));
				    ++desc;
                    off+=sizeof(*desc);
			    }
                printf("Imports at end at %x\n", (DWORD)((desc + 1 - descs) * sizeof(IMAGE_IMPORT_DESCRIPTOR)) + m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
                printf("Directory end %x\n", m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
		    }

		    ProcessIAT();
		    ProcessRelocations();
            PrintFunctionTable();
        }
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
            printf("%08x %08x %08x\n", entry.BeginAddress, entry.EndAddress, entry.UnwindInfoAddress);
            auto s = Rva2Section(entry.UnwindInfoAddress);
            if (s != nullptr)
            {
                printf("%s\n", s->Name);
                auto ui = Rva2Ptr<UNWIND_INFO>(entry.UnwindInfoAddress);
                printf("%u %u %s # codes %u\n", ui->Version, ui->Flags, ui->FlagString().c_str(), ui->CountOfCodes);
            }
        }
    }

    void AdjustResourceDirectory(char *resourceBase, IMAGE_RESOURCE_DIRECTORY *rsrc)
    {
        printf("Resource counts id %lx name %lx\n", rsrc->NumberOfIdEntries, rsrc->NumberOfNamedEntries);
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
                AdjustResourceDirectory(resourceBase, sub);
            }
            else
            {
                IMAGE_RESOURCE_DATA_ENTRY *data = (IMAGE_RESOURCE_DATA_ENTRY *)(resourceBase + entry->OffsetToData);
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
            printf("-- bb %lx %lx --\n", bb->start.ToUL(), bb->length);
            BBState state;
            Disassemble(bb->start, bb->length, [this, &state](const _CodeInfo &ci, Rva va, const _DInst &dinst) 
            { 
                Rva instva = va + dinst.addr;
                this->AdjustRIPOperand(ci, va, dinst, state); 
                if (dinst.opcode == I_RET || dinst.opcode == I_JMP)
                {
                    return false;
                }
                return true;
            });
            ++it;
        }
    }

    struct Insertion
    {
        Rva vaInsert;
        DWORD vaDelta;
    };

    std::vector<Insertion> insertions;

    std::unordered_map<Rva, Rva> m_replacementVas;

    void MoveVa(Rva oldVa, DWORD size, Rva newVa)
    {
        Insertion after;
        after.vaInsert = oldVa + size;
        after.vaDelta = 0;
        insertions.insert(insertions.begin(), after);
        Insertion move;
        move.vaInsert = oldVa;
        move.vaDelta = newVa - oldVa;
        insertions.insert(insertions.begin(), move);

        for (auto i : insertions)
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
        for (auto it = insertions.rbegin(); it != insertions.rend(); ++it)
        {
            if (*rva >= it->vaInsert)
            {
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
            *va = m_imageBase + tmp;
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

    void ExtendRData(DWORD extra)
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

        unsigned char *newData = (unsigned char *)calloc(s.m_section.SizeOfRawData + extra, 1);

        DWORD oldVaSize = (s.m_section.SizeOfRawData + 4095) & ~4095;
        DWORD newVaSize = (s.m_section.SizeOfRawData + extra + 4095) & ~4095;
        Insertion insert;
        insert.vaInsert = Rva(s.m_section.VirtualAddress + s.m_section.SizeOfRawData);
        insert.vaDelta = newVaSize - oldVaSize;
        printf("VA Insert %x VA delta %d\n", insert.vaInsert.ToUL(), insert.vaDelta);
        insertions.push_back(insert);
        memcpy(newData, s.m_rawData, s.m_section.SizeOfRawData);
        memset(newData + s.m_section.SizeOfRawData, '!', extra);

        unsigned char *inserted = newData + s.m_section.SizeOfRawData;

        s.m_rawData = newData;

        s.m_section.SizeOfRawData += extra;
        s.m_section.Misc.VirtualSize += extra;

        m_optionalHeader->SizeOfInitializedData += insertions.back().vaDelta;
        m_optionalHeader->SizeOfImage += insertions.back().vaDelta;

        OffsetRelocations();

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
            const char *symbols[] = { "malloc", "free", "realloc", "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize" };
            const char *replacement_symbols[] = { "wdm_malloc", "wdm_free", "wdm_realloc", "wdm_HeapAlloc", "wdm_HeapFree", "wdm_HeapReAlloc", "wdm_HeapSize" };
            unsigned int nSymbols = sizeof(symbols) / sizeof(symbols[0]);
            p = AddIINs(p, added, nSymbols, replacement_symbols);

            printf("added %x import orig %x\n", Ptr2Rva(added).ToUL(), added->OriginalFirstThunk);

            IMAGE_THUNK_DATA *newIat = (IMAGE_THUNK_DATA *)p;
            DWORD oldVa = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
            DWORD oldSize = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
            memcpy(newIat, Rva2Ptr<char *>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), oldSize);
            m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = Ptr2Rva(newIat).ToUL();
            for (unsigned int i = 0; i < descCount; ++i)
                newDescs[i].FirstThunk += Ptr2Rva(newIat).ToUL() - oldVa;
            m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size += (nSymbols + 1) * sizeof(IMAGE_THUNK_DATA);
            p +=  m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

            if (Ptr2Rva(p) >= insertions.back().vaInsert + insertions.back().vaDelta)
                printf("OVERFLOW of insertion\n");

            IMAGE_THUNK_DATA *f = newIat + (oldSize / sizeof(IMAGE_THUNK_DATA));
            added->FirstThunk = Ptr2Rva(f).ToUL();

            IMAGE_THUNK_DATA *of = Rva2Ptr<IMAGE_THUNK_DATA>(added->OriginalFirstThunk);
            Rva replacement(added->FirstThunk);
            for (unsigned int i = 0; i < nSymbols; ++i)
            {
                f->u1.AddressOfData = of->u1.AddressOfData;
                auto it = m_importedSymbols.find(symbols[i]);
                if (it != m_importedSymbols.end())
                {
                    m_replacementVas.insert(std::make_pair(it->second, replacement));
                }
                replacement += sizeof(IMAGE_THUNK_DATA);
                ++f;
                ++of;
            }
            f->u1.AddressOfData = 0;

            MoveVa(Rva(oldVa), oldSize, Ptr2Rva(newIat));
            printf("added %x import orig %x ft %x\n", Ptr2Rva(added).ToUL(), added->OriginalFirstThunk, added->FirstThunk);
        }

        PrintLoadConfig();

        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0)
        {
            IMAGE_TLS_DIRECTORY64 *tls = Rva2Ptr<IMAGE_TLS_DIRECTORY64>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
            AdjustVa(&tls->StartAddressOfRawData);
            printf("Start %llx\n", tls->StartAddressOfRawData);
            AdjustVa(&tls->EndAddressOfRawData);
            printf("End %llx\n", tls->EndAddressOfRawData);
            AdjustVa(&tls->AddressOfIndex);
            printf("Index %llx\n", tls->AddressOfIndex);
            AdjustVa(&tls->AddressOfCallBacks);
            printf("Callbacks %llx\n", tls->AddressOfCallBacks);
        }

        if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0)
        {
            IMAGE_RESOURCE_DIRECTORY *rsrc = Rva2Ptr<IMAGE_RESOURCE_DIRECTORY>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
            AdjustResourceDirectory((char *)rsrc, rsrc);
        }

        AdjustRIPAddresses();
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

    void Edit()
    {
        IMAGE_DATA_DIRECTORY oldImportDir = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_DATA_DIRECTORY oldIatDir = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

        ExtendRData(8192);

		if (m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
		{
			IMAGE_IMPORT_DESCRIPTOR *descs = Rva2Ptr<IMAGE_IMPORT_DESCRIPTOR>(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			IMAGE_IMPORT_DESCRIPTOR *desc = descs;
			while (desc->Name != 0)
			{
				char *name = Rva2Ptr<char>(desc->Name);

				printf("Name %s, %s\n", name, Rva2Section(desc->Name)->Name);

#if 0
                if (strcmp(name, "api-ms-win-crt-heap-l1-1-0.dll") == 0)
                {
                    printf("edit DLL name\n");
                    strcpy(name, "api-ix-win-crt-heap-l1-1-0.dll");
                }
#endif
				++desc;
			}
		}
    }

	void ProcessIAT()
	{
        DWORD size = m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
		if (size != 0)
		{
			printf("IAT dir %x size %d\n", Rva2Offset(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress), size);
            DWORD64 *entries = Rva2Ptr<DWORD64>(Rva(m_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress));
            DWORD nEntries = size / sizeof(*entries);
            for (unsigned int i = 0; i < nEntries; ++i)
            {
                DWORD64 e = entries[i];
                printf("%llx\n", e);
                if (e != 0 && !GetTopBit(e))
                {
                    IMAGE_IMPORT_BY_NAME *iin = Rva2Ptr<IMAGE_IMPORT_BY_NAME>(Rva(e));
                    if (iin == nullptr)
                        printf("bad iin\n");
                    else
                        printf("iin %s\n", iin->Name);
                }
            }
		}
	}

	void ProcessRelocations()
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

                        //printf("dir64 %lx %llx\n", reloc->VirtualAddress + relOffset, addr);

                        Rva rva(addr - m_imageBase);
                        if (AdjustRva(&rva))
                        { 
                            addr = rva.ToUL() + m_imageBase;
                        }
                    }
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
		unsigned char *m_base;
		off_t m_originalLength;
		int m_nSections;
		IMAGE_SECTION_HEADER *m_sectionHeaders;
        std::vector<SECTION> m_sections;
		IMAGE_OPTIONAL_HEADER64 *m_optionalHeader;
		ULONGLONG m_imageBase;
};

int PEFile::BasicBlock::nextId;

int main(int argc, char *argv[])
{
    bool disassem = false;
    bool verbose = false;
    std::vector<const char *> filenames;
    bool edit = false;
    const char *out_filename = nullptr;
    const char *out_directory = nullptr;

    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-')
        {
            if (strcmp(argv[i], "-dis") == 0)
                disassem = true;
            else if (strcmp(argv[i], "-edit") == 0)
                edit = true;
            else if (strcmp(argv[i], "-v") == 0)
                verbose = true;
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
        }
        else
        {
            filenames.push_back(argv[i]);
        }
    }

    if (edit && (out_filename == nullptr && out_directory == nullptr))
    {
        fprintf(stderr, "expect -out <filename> or -outd <directory>\n");
        exit(EXIT_FAILURE);
    }

    bool failed = false;
    for (auto filename : filenames)
    { 
        try
        { 
            PEFile file(filename);

            if (edit)
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
	            file.Process(disassem, verbose);
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
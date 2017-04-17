#include "Disassemble.h"
#include "Rva.h"

void Disassemble(const unsigned char *buf, Rva va, DWORD size, InstructionHandler handler)
{
	const int MAX_INSTRUCTIONS = 1000;
	
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

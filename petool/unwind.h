#pragma once

#include <string>
#include <windows.h>

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

// UNWIND_INFO see https://docs.microsoft.com/en-us/cpp/build/struct-unwind-info?view=vs-2017
// UNWIND_CODE see https://docs.microsoft.com/en-us/cpp/build/struct-unwind-code?view=vs-2017
// More useful reference in coreclr e.g. https://github.com/dotnet/coreclr/blob/master/src/inc/win64unwind.h

enum class UWOP
{  
    PUSH_NONVOL = 0, /* info == register number */  
    ALLOC_LARGE,     /* no info, alloc size in next 2 slots */  
    ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */  
    SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */  
    SAVE_NONVOL,     /* info == register number, offset in next slot */  
    SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */  
    SAVE_XMM128,     /* info == XMM reg number, offset in next slot */  
    SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */  
    PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */  
};

union UNWIND_CODE
{
    struct 
    {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };

    USHORT FrameOffset;
};

typedef struct UNWIND_INFO 
{
    BYTE Version         : 3;
    BYTE Flags           : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister  : 4;
    BYTE FrameOffset    : 4;
    UNWIND_CODE UnwindCodes[1];

    std::string FlagString() const
    {
        if (Flags == UNW_FLAG_NHANDLER)
            return "nhandler";
        std::string r;
        if ((Flags & UNW_FLAG_EHANDLER) != 0)
            r += "ehandler";
        if ((Flags & UNW_FLAG_UHANDLER) != 0)
            r += " uhandler";
        if ((Flags & UNW_FLAG_CHAININFO) != 0)
            r += " chaininfo";
        return r;
    }


    union HandlerInfo
    {
        //
        // If (Flags & UNW_FLAG_EHANDLER)
        //
        struct
        {
            ULONG ExceptionHandler;
            ULONG ExceptionHandlerData;
        } EHandler;

        //
        // Else if (Flags & UNW_FLAG_CHAININFO)
        //
        struct
        {
            ULONG FunctionStartAddress;
            ULONG FunctionEndAddress;
            ULONG UnwindInfoAddress;
        } FunctionEntry;
    };

    const HandlerInfo &GetHandlerInfo() const
    {
        unsigned int count = this->CountOfCodes;
        if ((count & 1) != 0)
            ++count;
        return *(const HandlerInfo *)((const char *)this + 4 + count * sizeof(UNWIND_CODE));
    }
#if 0
    //
    // If (Flags & UNW_FLAG_EHANDLER)
    //
    OPTIONAL ULONG ExceptionData[];
#endif
} *PUNWIND_INFO;


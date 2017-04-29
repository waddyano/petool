#pragma once

#include <string>
#include <windows.h>

#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

// UNWIND_INFO see https://msdn.microsoft.com/en-us/library/ddssxxy8.aspx
// UNWIND_CODE see https://msdn.microsoft.com/en-us/library/ck9asaa9.aspx

struct UNWIND_CODE
{
    BYTE Offset;
    BYTE UnwindOperationCode : 4;
    BYTE OperationInfo : 4;
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
        ULONG ExceptionHandler;
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


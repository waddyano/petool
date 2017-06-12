#pragma once

#include <windows.h>
#pragma warning(push)
#pragma warning(disable : 4091)  
#include <DbgHelp.h>
#pragma warning(pop)

namespace Utils
{
    __declspec(noinline)
    ULONG Traceback(DWORD64 *traceback, ULONG maxDepth)
    {
        CONTEXT context;

	    RtlCaptureContext(&context);

	    for (ULONG frame = 0; ; ++frame)
	    {
            if (frame == maxDepth)
                return frame;
            traceback[frame] = context.Rip;
            
		    //
		    // Try to look up unwind metadata for the current function.
		    //
            ULONG64 imageBase;
    	    PRUNTIME_FUNCTION runtimeFunction = RtlLookupFunctionEntry(context.Rip, &imageBase, nullptr);
		    if (runtimeFunction == nullptr)
		    {
			    //
			    // If we don't have a RUNTIME_FUNCTION, then we've encountered
			    // a leaf function.  Adjust the stack approprately.
			    //

			    context.Rip  = (ULONG64)(*(PULONG64)context.Rsp);
			    context.Rsp += 8;
		    }
		    else
		    {
        	    KNONVOLATILE_CONTEXT_POINTERS nvContext;

		        RtlZeroMemory(&nvContext, sizeof(KNONVOLATILE_CONTEXT_POINTERS));

                PVOID handlerData;
                ULONG64 establisherFrame;
			    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, context.Rip, runtimeFunction, &context, &handlerData, &establisherFrame, &nvContext);
		    }

            if (context.Rip == 0)
			    return frame;
	    }
    }

    class SymbolHandler
    {
    public:
        SymbolHandler()
        {
            m_symbolInfo = (PSYMBOL_INFO)m_buffer;

            DWORD Options = ::SymGetOptions(); 
            Options |= SYMOPT_DEBUG; 
            ::SymSetOptions( Options ); 

            m_initialized = ::SymInitialize( GetCurrentProcess(), NULL, TRUE) != 0;
        }

        const char *LookupSymbol(DWORD64 addr)
        {
            DWORD64   baseAddr  = 0; 
		    DWORD     dllSize  = 0; 
    	    //DWORD64 modBase = ::SymLoadModule64(GetCurrentProcess(), NULL, pFileName, NULL,	baseAddr, dllSize);
            m_symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
            m_symbolInfo->MaxNameLen = 2048;
            DWORD64 disp;
            if (::SymFromAddr(GetCurrentProcess(), addr, &disp, m_symbolInfo) == 0)
                return nullptr;
            return m_symbolInfo->Name;
        }


    private:
        PSYMBOL_INFO m_symbolInfo;
        unsigned char m_buffer[sizeof(SYMBOL_INFO) + 2048];
        bool m_initialized;
    };
}
#pragma once

class Options
{
public:
    Options()
    {
    }

    bool Disassemble = false;
    bool PrintExports = false;
    bool PrintImports = false;
    bool PrintImportedDLLs = false;
    bool Verbose = false;
    bool Edit = false;
    bool FixedAddress = false;
};
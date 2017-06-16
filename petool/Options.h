#pragma once

class Options
{
public:
    Options()
    {
    }

    bool Disassemble = false;
    bool PrintImports = false;
    bool PrintImportedDLLs = false;
    bool Verbose = false;
    bool Edit = false;
    bool FixedAddress = false;
};
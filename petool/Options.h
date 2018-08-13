#pragma once

class Options
{
public:
    Options()
    {
    }

    bool Disassemble = false;
    bool PrintDirectories = false;
    bool PrintExports = false;
    bool PrintImports = false;
    bool PrintImportedDLLs = false;
    bool FindVTables = false;
    bool Verbose = false;
    bool ExtraVerbose = false;
    bool Edit = false;
    bool FixedAddress = false;
};
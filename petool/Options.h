#pragma once

class Options
{
public:
    Options() : Disassemble(false), PrintImports(false), Verbose(false), Edit(false)
    {
    }

    bool Disassemble;
    bool PrintImports;
    bool Verbose;
    bool Edit;
    bool FixedAddress;
};
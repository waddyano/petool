#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include "Rva.h"

class ImportedDLL;

class ImportedSymbol
{
public:
    ImportedSymbol(ImportedDLL *dll, const std::string &name, Rva addressRva) : m_dll(dll), m_name(name), m_addressRva(addressRva)
    {
    }

    const std::string &GetName() const
    {
        return m_name;
    }

    Rva GetAddressRva() const
    {
        return m_addressRva;
    }

private:
    ImportedDLL *m_dll;
    std::string m_name;
    Rva m_addressRva;
};

class ImportedDLL
{
    friend class ImportedDLLs;
public:
    ImportedDLL(const std::string &name, bool delayed) : m_name(name), m_delayed(delayed)
    {
    }

    ImportedSymbol *AddImportedSymbol(const std::string &name, Rva addressRva)
    {
        ImportedSymbol *symbol = new ImportedSymbol(this, name, addressRva);
        m_symbols.push_back(symbol);
        return symbol;
    }

    ImportedSymbol *Find(const char *name) const
    {
        for (auto s : m_symbols)
            if (s->GetName() == name)
                return s;
        return nullptr;
    }

private:
    std::string m_name;
    bool m_delayed;
    std::vector<ImportedSymbol *> m_symbols;
};

class ImportedDLLs
{
public:
    ImportedDLLs()
    {
    }

    ImportedDLL *AddImportedDLL(const std::string &name, bool delayed)
    {
        m_importedDLLs.push_back(new ImportedDLL(name, delayed));
        return m_importedDLLs.back();
    }

    void AddImportedSymbol(ImportedDLL *dll, const std::string &name, Rva addressRva)
    {
        ImportedSymbol *symbol = dll->AddImportedSymbol(name, addressRva);
        m_vaToImportedSymbols.insert(std::make_pair(addressRva, symbol));
    }

    const char *Find(Rva rva)
    {
        auto it = m_vaToImportedSymbols.find(rva);
        if (it == m_vaToImportedSymbols.end())
            return nullptr;
        return it->second->GetName().c_str();
    }

    Rva Find(const char *symbol)
    {
        for (auto dll : m_importedDLLs)
        {
            ImportedSymbol *sym = dll->Find(symbol);
            if (sym != nullptr)
                return sym->GetAddressRva();
        }
        return Rva();
    }
private:
    std::vector<ImportedDLL *> m_importedDLLs;
	std::unordered_map<Rva, ImportedSymbol *> m_vaToImportedSymbols;
};
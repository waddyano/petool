#pragma once
#include <string>

class ConfigFile
{
public:
    ConfigFile(const char *name) : m_filename(name)
    {

    }
    void Load();
private:
    std::string m_filename;
};
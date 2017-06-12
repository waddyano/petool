#define _CRT_SECURE_NO_WARNINGS
#include <fstream>
#include <stdio.h>
#include "ConfigFile.h"
#include "toml.h"

void ConfigFile::Load()
{
    std::ifstream ifs(m_filename);
    toml::ParseResult pr = toml::parse(ifs);
    if (!pr.valid())
    {
        printf("failed: %s\n", pr.errorReason.c_str());
        return;
    }

    auto val = pr.value;
    printf ("type %d\n", val.type());
    auto redirects = val.find("redirects");
    printf ("redirect type %d\n", val.type());
    if (redirects == nullptr)
    {
        printf("null redir\n");
        return;
    }

    const toml::Table& tab = redirects->as<toml::Table>();
    for (const auto& e : tab) 
    {
        printf("tab elem %s %d\n", e.first.c_str(), e.second.type());
        const toml::Table& tab2 = e.second.as<toml::Table>();
        for (const auto& e2 : tab2)
        { 
            printf("tab2 elem %s %s\n", e2.first.c_str(), e2.second.as<std::string>().c_str());
        }
    }
}

#pragma once
#include <functional>
#include <limits.h>
#include <stdio.h>

class Rva
{
public:
    Rva() : m_va(0)
    {
    }

    explicit Rva(unsigned long va) : m_va(va)
    {
    }

    explicit Rva(unsigned long long va)
    {
        if (va > ULONG_MAX)
            printf("va too large! %llx\n", va);
        m_va = (unsigned long) va;
    }

    unsigned long ToUL() const
    {
        return m_va;
    }

    static Rva Invalid()
    {
       return Rva(~0ul);
    }

    inline bool IsZero() const
    {
        return m_va == 0;
    }

    inline Rva operator + (long long off) const
    {
        return Rva(m_va + (long)off);
    }

    inline Rva operator - (long long off) const
    {
        return Rva(m_va - (long)off);
    }

    inline Rva &operator += (long long off)
    {
        m_va += (long)off;
        return *this;
    }

    inline int operator - (Rva other) const
    {
        if (m_va > other.m_va)
            return m_va - other.m_va;
        else if (other.m_va > m_va)
            return - (int)(other.m_va - m_va);
        return 0;
    }

    inline bool operator == (Rva other) const
    {
        return m_va == other.m_va;
    }

    inline bool operator != (Rva other) const
    {
        return m_va != other.m_va;
    }

    inline bool operator < (Rva other) const
    {
        return m_va < other.m_va;
    }

    inline bool operator <= (Rva other) const
    {
        return m_va <= other.m_va;
    }
    inline bool operator > (Rva other) const
    {
        return m_va > other.m_va;
    }

    inline bool operator >= (Rva other) const
    {
        return m_va >= other.m_va;
    }
private:
    unsigned long m_va;
};

namespace std
{ 
    template <>
    struct hash<Rva>
    {
        size_t operator()(const Rva& val) const
        {
            return std::hash<unsigned long>()(val.ToUL());
        }
    };
}

#pragma once

enum class TargetType
{
    FUNCTION,
    CFUNCTION,
    RFUNCTION,
    LABEL,
    ENTRY,
    DATA
};

struct TargetInfo
{
	explicit TargetInfo(TargetType t) : targetType(t), defined(false)
	{
	}
	explicit TargetInfo(TargetType t, bool d) : targetType(t), defined(d)
	{
	}
    TargetType targetType;
	bool defined;
};

extern inline char *ToString(TargetType type)
{
    switch (type)
    {
    case TargetType::FUNCTION:
        return "fn";
    case TargetType::CFUNCTION:
        return "cfn";
    case TargetType::RFUNCTION:
        return "rfn";
    case TargetType::LABEL:
        return "lab";
    case TargetType::ENTRY:
        return "entry";
    case TargetType::DATA:
        return "dat";
    default:
        return "???";
    }
}


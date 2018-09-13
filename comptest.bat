cl /GS /W3 /Gy /Zc:wchar_t /Zi /Gm- /O2 ^
/Zc:inline /fp:precise /D "IN_DLL" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" /D "TESTDLL_EXPORTS" /D "_WINDLL" /D "_UNICODE" /D "UNICODE" /errorReport:prompt ^
/WX- /Zc:forScope /Gd /Oi /MD /EHsc /nologo /Fa /c test-dll\test.cpp 
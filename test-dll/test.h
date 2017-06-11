#pragma once

#ifdef IN_DLL
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif

extern EXPORT int dllfn3(char c);
extern EXPORT void crit();
extern EXPORT void dllfn1();
extern EXPORT void dllfn2(int i, int j);
extern EXPORT bool excpt(bool seh);
extern EXPORT void excpt2(int i);



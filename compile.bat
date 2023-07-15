@ECHO OFF

:: no import table
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /DNO_IMPORT_TABLE /Tp implant.cpp helpers.cpp /link /OUT:implant.exe /SUBSYSTEM:WINDOWS /MACHINE:x64

del *.obj

cl.exe /W0 /GS- /DNDEBUG /D_USRDLL /D_WINDLL implantDll.cpp helpers.cpp /MT /link /DLL /OUT:implant.dll

del *.obj

:: import table
:: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:implant.exe /SUBSYSTEM:WINDOWS /MACHINE:x64

:: terminal binary
:: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:implant.exe

del cryptDef.h
del dropper.bin

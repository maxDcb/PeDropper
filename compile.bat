@ECHO OFF

:: no import table
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /DNO_IMPORT_TABLE /Tp *.cpp /link /OUT:implant.exe /SUBSYSTEM:WINDOWS /MACHINE:x64

:: import table
:: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:implant.exe /SUBSYSTEM:WINDOWS /MACHINE:x64

:: terminal binary
:: cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:implant.exe

del cryptDef.h
del *.obj
del dropper.bin

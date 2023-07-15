#!/bin/bash

x86_64-w64-mingw32-g++ -Wl,-subsystem,windows -s -Os -Wno-narrowing implant.cpp helpers.cpp -o implant.exe

x86_64-w64-mingw32-g++ -shared -Wl,-subsystem,windows -s -Os -Wno-narrowing implantDll.cpp helpers.cpp -o implant.dll

rm cryptDef.h
rm dropper.bin
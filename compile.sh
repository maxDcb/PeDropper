#!/bin/bash

x86_64-w64-mingw32-g++ -Wl,-subsystem,windows -s -Os -Wno-narrowing *.cpp -o implant.exe

rm cryptDef.h
rm dropper.bin
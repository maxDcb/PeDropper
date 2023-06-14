# GenerateDropperBinary

sudo apt install gcc-mingw-w64  
sudo apt install g++-mingw-w64  
pip3 install pycryptodome  

Generate a dropper for any DLL or EXE. The shellcode of the payload is generated with [Donut](https://github.com/TheWover/donut). The dropper is compile with the generated shellcode (credit to sektor7). The exe resulting has no import table, every function name are xored and the payload is AES encrypted. 


Compatible with linux and windows.  

![alt text](https://github.com/maxDcb/PeDropper/blob/master/ressources/image1.png?raw=true)
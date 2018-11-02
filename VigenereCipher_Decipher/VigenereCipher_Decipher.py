""" DeCrypting the Cipher text without having the key
	is done by finding the key length and the possible keys
	using the key the cipher text is decryted using VIGENERE CIPHER
	
	There is possibility of having diffrent keys to decipher the text

	Done by RISHIKESH RAM S"""

from itertools import starmap,cycle
from collections import Counter
import numpy as np
import sys


"""decrypting chiper text with given key"""

def decryptMsg(chiperText ,key ):
	return "".join(starmap(lambda x ,y: chr(((ord(x) - ord(y)) % 26) + ord('A')), zip(chiperText, cycle(key))))

"""Method calculates the letter Frequency"""

def letterFreq(chiperText):
	return Counter(chiperText)

"""Method calculates the index of coincidence in the cipherText"""

def indexOfCoincidence(subChiperText):
	ct_len = len(subChiperText)
	char = 26.0
	lF = letterFreq(subChiperText)
	number = float((ct_len*(ct_len-1))/char)
	
	freqSum = 0.0
	for a in lF:
		freqSum += float((lF[a]*(lF[a]-1))) 	
	if(number == 0 ):
		return 0.0
	return freqSum/number

"""Method calculates the possible key length"""

def possibleKeyLength(chiperText):
	pkl = {}
	possibleKeyLen = []
	for i in range(1,16):
		
		iCAvg = 0.0
		IC = 0.0
		for j in range(i):
			
			subString =''
			for s in range(len(chiperText)):
				if(s%i == j):

					subString+=chiperText[s]
			
			IC +=  indexOfCoincidence(subString)	
		iCAvg = IC/float(i)
		pkl[i] = iCAvg
	
	predict = 1.73
	for i  in pkl.copy():
		if(abs(pkl[i] - 1.73) < 0.20 ):
			possibleKeyLen.append(i)
		
	return possibleKeyLen

"""split the chiper text for rows in size of given key length ,and transpose them into columns"""

def splitForColumns(chiperText  , colLenght):
	subs = []
	n = colLenght
	subs = np.array(["".join(chiperText[i:i+n]) for i in range(0, len(chiperText), n)])
	s =[]
	preLenght = subs[0]
	pieces = []

	for i in range(n):
		piece = ""
		for j in range(len(subs)):
			try:
				piece+=subs[j][i]
			except IndexError:
				piece+=""
		pieces.append(piece)
	return pieces


"""Mthod find the possible key for the key length"""

def possibleKey(cols):

	engLetterFreqs = { 'A' : 8.167 ,'B' : 1.492,'C' : 2.782, 'D' : 4.253, 'E' : 12.702, 'F' : 2.228,'G' : 2.015,'H' : 6.094,'I' : 6.966,'J' : 0.153,'K' : 0.772,'L' : 4.025,'M' : 2.406,'N' : 6.749,'O' : 7.507,'P' : 1.929,'Q' : 0.095,'R' : 5.987,'S' : 6.327,'T' : 9.056,'U' : 2.758,'V' : 0.978,'W' : 2.361,'X' : 0.150,'Y' : 1.974,'Z' : 0.074 }
	letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	key=''
	for i in cols:
		res=[]
		
		for j in letters:
			
			dec = decryptMsg(i ,j)
			freqs = letterFreq(dec)
			X = 0.0
			
			for l in freqs:
				X+= float((freqs[l])*engLetterFreqs[l]*100)/float(len(i))
			res.append((j,X))
		
		
		key+= max(res , key=lambda x: x[1])[0]
	return key
		
""" Vigenere Decrypt method decrypts the cipher text with the possible keys found"""

def vigenereDecrypt(chiper):
	sChiper = ''.join(filter(str.isalpha, chiper)).upper()
	""" finding the possible key length """
	keys_Length = possibleKeyLength(sChiper)

	print("Possible key length are as follows:" , keys_Length)
	for i in keys_Length:
		sCols = splitForColumns(sChiper , i)
		key = possibleKey(sCols)
		"""Decrypt message method is called"""
		plainText = decryptMsg(sChiper , key)
		print('key in length : ' , i)
		print('possible key :' , key)
		print('Decrypted message  :' , plainText)


""" The GetCipherTextFrom File method reads teh file and get the ciphertext"""

def getCipherTextFromFile(fileName):
    file=open(fileName,"r")
    cipher_Text=file.readline()
    print("------Lets Start to DeChiper------")
    print("Cipher Text: "+cipher_Text)
    return cipher_Text
 
if __name__ == '__main__':
    try:
        fileName="cipherText.txt"
        """cipherText variable contains the cipher text"""
        cipherText = getCipherTextFromFile(fileName)
        
        """ When the cipherText variables doesnot have any text in it , empty message
        is printed otherwise the text is decrypted"""

        if cipherText != None and len(cipherText) > 0 :
            vigenereDecrypt(cipherText)
        else:
            print("Empty message")

    except Exception as e :
        print (e)        

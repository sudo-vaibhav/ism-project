# !pip install pyngrok
import json
from flask import Flask, request
import requests
import threading
from pyngrok import ngrok

import sys

# set enums
ECB =	1
PAD_PKCS5 = 1


class desClass(object):
	def __init__(self, mode=ECB, padmode=PAD_PKCS5):
		self.block_size = 8
		self.cipherMode = mode
		self.initializationVector = None
		self.paddingMode = padmode

	def getKey(self):
		return self.key

	def setKey(self, key):
		key = self.formatForProcessing(key)
		self.key = key

	def addDataPadding(self, data):
		#PAD_PKCS5
		pad_len = 8 - (len(data) % self.block_size)
		data += bytes([pad_len] * pad_len)

		return data

	def removePadding(self, data):
		if not data:
			return data
		# PAD_PKCS5
		pad_len = data[-1]
		data = data[:-pad_len]

		return data

	def formatForProcessing(self, data):
		if isinstance(data, str):
			return data.encode('ascii')
		return data

class des(desClass):
	# initial permutation IP
	ip = [57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8,  0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
	]
 
	# Permutation and translation tables for DES
	pc1 = [56, 48, 40, 32, 24, 16,  8,
		  0, 57, 49, 41, 33, 25, 17,
		  9,  1, 58, 50, 42, 34, 26,
		 18, 10,  2, 59, 51, 43, 35,
		 62, 54, 46, 38, 30, 22, 14,
		  6, 61, 53, 45, 37, 29, 21,
		 13,  5, 60, 52, 44, 36, 28,
		 20, 12,  4, 27, 19, 11,  3
	]

	# number left rotations of pc1
	left_rotat = [
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	]

	# permuted choice key (table 2)
	pc2 = [
		13, 16, 10, 23,  0,  4,
		 2, 27, 14,  5, 20,  9,
		22, 18, 11,  3, 25,  7,
		15,  6, 26, 19, 12,  1,
		40, 51, 30, 36, 46, 54,
		29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52,
		45, 41, 49, 35, 28, 31
	]

	

	# Expansion table for turning 32 bit blocks into 48 bits
	expansion = [
		31,  0,  1,  2,  3,  4,
		 3,  4,  5,  6,  7,  8,
		 7,  8,  9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31,  0
	]

	# The (in)famous S-boxes
	sBox = [
		# S1
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

		# S2
		[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

		# S3
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

		# S4
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

		# S5
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

		# S6
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

		# S7
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

		# S8
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]


	# 32-bit permutation function P used on the output of the S-boxes
	pBox = [
		15, 6, 19, 20, 28, 11,
		27, 16, 0, 14, 22, 25,
		4, 17, 30, 9, 1, 7,
		23,13, 31, 26, 2, 8,
		18, 12, 29, 5, 21, 10,
		3, 24
	]

	# final permutation IP^-1
	finalPermu = [
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24
	]

	# crypt literals
	ENCRYPT =	0x00
	DECRYPT =	0x01

	# Initialisation
	def __init__(self, key, mode=ECB, padmode=PAD_PKCS5):
		if len(key) != 8:
			raise ValueError("Invalid DES key size. need 8 bytes long.")
		desClass.__init__(self, mode, padmode)

		self.L = []
		self.R = []
		self.Kn = [ [0] * 48 ] * 16	# 16 48-bit keys (K1 - K16)
		self.final = []
		self.keySize = 8
		self.setKey(key)

	def setKey(self, key):
		desClass.setKey(self, key)
		self.generateSubKeys()

	def stringToBits(self, data):
		length = len(data) * 8
		answer = [0] * length
		pos = 0
		for character in data:
			idx = 7
			while idx >= 0:
				if character & (1 << idx) != 0:
					answer[pos] = 1
				else:
					answer[pos] = 0
				pos += 1
				idx -= 1

		return answer

	def convertToString(self, data):
		"""Convert bits into str"""
		result = []
		pos = 0
		c = 0
		while pos < len(data):
			c += data[pos] << (7 - (pos % 8))
			if (pos % 8) == 7:
				result.append(c)
				c = 0
			pos += 1
		return bytes(result)

	def permuteBlock(self, table, block):
		"""Permutate this block with the specified table"""
		return list(map(lambda x: block[x], table))
	
	# generate subkeys for each step of DES
	def generateSubKeys(self):
		KEY = self.permuteBlock(des.pc1, self.stringToBits(self.getKey()))
		i = 0
		# Split l and r
		self.L = KEY[:28]
		self.R = KEY[28:]
		while i < 16:
			j = 0
			# Perform circular left shifts
			while j < des.left_rotat[i]:
				self.L.append(self.L[0])
				del self.L[0]

				self.R.append(self.R[0])
				del self.R[0]

				j += 1

			# Create one of the 16 subkeys through pc2 permutation
			self.Kn[i] = self.permuteBlock(des.pc2, self.L + self.R)
			i += 1

	# the actual encryption algo
	def __des_crypt(self, block, crypt_type):
		block = self.permuteBlock(des.ip, block)
		self.L = block[:32]
		self.R = block[32:]

		# Encryption starts from Kn[1] through to Kn[16]
		if crypt_type == des.ENCRYPT:
			iter = 0
			iterAdjust = 1
		# Decryption starts from Kn[16] down to Kn[1]
		else:
			iter = 15
			iterAdjust = -1

		i = 0
		while i < 16:
			# Make a copy of R[i-1], this will later become L[i]
			tempR = self.R[:]

			# Permutate R[i - 1] to start creating R[i]
			self.R = self.permuteBlock(des.expansion, self.R)

			# Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
			self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iter]))
			B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]

			# Permutate B[1] to B[8] using the S-Boxes
			j = 0
			Bn = [0] * 32
			pos = 0
			while j < 8:
				# find offsets
				m = (B[j][0] << 1) + B[j][5]
				n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

				# Find the permutation value
				v = des.sBox[j][(m << 4) + n]

				# Turn value into bits, add it to result: Bn
				Bn[pos] = (v & 8) >> 3
				Bn[pos + 1] = (v & 4) >> 2
				Bn[pos + 2] = (v & 2) >> 1
				Bn[pos + 3] = v & 1

				pos += 4
				j += 1

			# Permutate the concatenation of B[1] to B[8] (Bn)
			self.R = self.permuteBlock(des.pBox, Bn)

			# Xor with L[i - 1]
			self.R = list(map(lambda x, y: x ^ y, self.R, self.L))

			# L[i] becomes R[i - 1]
			self.L = tempR

			i += 1
			iter += iterAdjust
		
		# Final permutation of R[16]L[16]
		self.final = self.permuteBlock(des.finalPermu, self.R + self.L)
		return self.final


	# Data to be encrypted/decrypted
	def crypt(self, data, crypt_type):
		"""Crypt the data in blocks, running it through des_crypt()"""
		if not data:
			return ''
		# Split the data into blocks, crypting each one seperately
		i = 0
		result = []
		while i < len(data):
			block = self.stringToBits(data[i:i+8])
			processed_block = self.__des_crypt(block, crypt_type)
			result.append(self.convertToString(processed_block))
			i += 8
		return bytes.fromhex('').join(result)

	def encrypt(self, data):
		data = self.formatForProcessing(data)
		if pad is not None:
			pad = self.formatForProcessing(pad)
		data = self.addDataPadding(data)
		return self.crypt(data, des.ENCRYPT)

	def decrypt(self, data):
		data = self.formatForProcessing(data)
		if pad is not None:
			pad = self.formatForProcessing(pad)
		data = self.crypt(data, des.DECRYPT)
		return self.removePadding(data, pad)

class triple_des(desClass):
	def __init__(self, key, mode=ECB, padmode=PAD_PKCS5):
		desClass.__init__(self, mode, padmode)
		self.setKey(key)

	def setKey(self, key):
		self.key_size = 16
		if len(key) != self.key_size:
			raise ValueError("Invalid 3DES key. Must be 16 bytes long")

		self.KEY1 = des(key[:8], self.cipherMode, self.paddingMode)
		self.KEY2 = des(key[8:16], self.cipherMode, self.paddingMode)
		self.KEY3 = self.KEY1
		desClass.setKey(self, key)

	def encrypt(self, data):
		ENCRYPT = des.ENCRYPT
		DECRYPT = des.DECRYPT
		data = self.formatForProcessing(data)
		data = self.addDataPadding(data)
		data = self.KEY1.crypt(data, ENCRYPT)
		data = self.KEY2.crypt(data, DECRYPT)
		return self.KEY3.crypt(data, ENCRYPT)

	def decrypt(self, data):
		ENCRYPT = des.ENCRYPT
		DECRYPT = des.DECRYPT
		data = self.formatForProcessing(data)
		data = self.KEY3.crypt(data, DECRYPT)
		data = self.KEY2.crypt(data, ENCRYPT)
		data = self.KEY1.crypt(data, DECRYPT)
		return self.removePadding(data)
	
class TripleDESFlaskWrapper:
	def __init__(self,key="ABCDEFGHIJKLMNOP"):
		self.tripleDESObject = triple_des(key,padmode=PAD_PKCS5)
	def encrypt(self,data:str):
		return self.tripleDESObject.encrypt(data.encode("utf-8"))
	def getEncodedMessage(self,data):
		print("received encrypt request for the string",data)
		res = self.encrypt(data)
		print("result after encryption was",res)
		return list(res)
	def decrypt(self,encrypted:bytes):
		return self.tripleDESObject.decrypt(encrypted).decode("utf-8")

obj = TripleDESFlaskWrapper()
x=obj.encrypt("abcモーニング asasfsf")
print(x)
print(obj.decrypt(x))
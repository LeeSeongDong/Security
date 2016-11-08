#pragma once
#ifndef __AES_H__
#define __AES_H__

#include "common.h"


class AES
{
private :
	 byte state[NK][NB];
	 byte key[NK][NB*(NR + 1)];
	
	 

public :
	AES() {}
	~AES() {}

	byte GFMultiplication(byte a, byte b);

	void encryption(byte* in, byte* out, byte* key);
	void decryption(byte* in, byte* out, byte* key);

	void setState(byte* in);
	void setOut(byte* out);

	void keyExpansion();

	void setKey(byte* key);

	byte sBox(byte b);
	byte revSBox(byte b);

	void subBytes();
	void revSubBytes();

	void shiftRows();
	void revShiftRows();

	void mixCols();
	void revMixCols();

	void addRoundKey(int round);

	void printState();
	void printKey();
};

#endif
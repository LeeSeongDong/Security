#include "AES.h"

byte AES::GFMultiplication(byte a, byte b)
{
	byte res = 0x00, temp = a;
	byte mask = 0x01;

	// 00011011 = 0x1B
	for (int i = 0; i < 8; ++i)
	{
		if (b & mask)
		{
			res ^= temp;
		}

		temp <<= 1;
		if (temp & 0x80)
		{
			temp ^= 0x1B;
		}

		mask <<= 1;
	}


	return res;
}

void AES::encryption(byte* in, byte* out, byte* key)
{
	setState(in);
	setKey(key);

	keyExpansion();

	printf_s("Input State : \n");
	printState();
	printf_s("Key : \n");
	printKey();

	addRoundKey(0);

	for (int i = 1; i < NR; ++i)
	{
		subBytes();
		shiftRows();
		mixCols();
		addRoundKey(i);
	}

	subBytes();
	shiftRows();
	addRoundKey(NR);

	printf_s("Output State : \n");
	printState();

	setOut(out);
}

void AES::decryption(byte * in, byte * out, byte* key)
{
	setState(in);
	setKey(key);
	keyExpansion();

	printf_s("\nDecryption\nInput State : \n");
	printState();
	printf_s("Key : \n");
	printKey();

	addRoundKey(NR);

	for (int i = NR-1; i > 0; --i)
	{
		revShiftRows();
		revSubBytes();
		addRoundKey(i);
		revMixCols();
	}

	revShiftRows();
	revSubBytes();
	addRoundKey(0);

	printf_s("Output State : \n");
	printState();

	setOut(out);
}


void AES::setState(byte* in)
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			state[j][i] = in[i * 4 + j];
		}
	}
}

void AES::setOut(byte * out)
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			out[j * 4 + i] = state[i][j];
		}
	}
}

void AES::keyExpansion()
{
	// round 1 ~ NR
	byte rcon[NR] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
	for (int i = 1; i < NR+1; ++i)
	{
		key[0][i*NB] = key[0][(i-1)*NB] ^ sBox(key[1][i*NB - 1]) ^ rcon[i - 1];
		key[1][i*NB] = key[1][(i-1)*NB] ^ sBox(key[2][i*NB - 1]);
		key[2][i*NB] = key[2][(i-1)*NB] ^ sBox(key[3][i*NB - 1]);
		key[3][i*NB] = key[3][(i-1)*NB] ^ sBox(key[0][i*NB - 1]);

		for (int j = 1; j < NB; ++j)
		{
			for (int k = 0; k < NK; ++k)
			{
				key[k][i*NB + j] = key[k][i*NB + j - 1] ^ key[k][i*NB + j - NB];
			}
		}
	}
}

void AES::setKey(byte* key)
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			this->key[i][j] = key[i*NK + j];
		}
	}
}

byte AES::sBox(byte b)
{
	return fsb[b];
}

byte AES::revSBox(byte b)
{
	return rsb[b];
}

void AES::subBytes()
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			state[i][j] = sBox(state[i][j]);
		}
	}
}

void AES::revSubBytes()
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			state[i][j] = revSBox(state[i][j]);
		}
	}
}

void AES::shiftRows()
{
	byte temp1, temp2;
	// row1
	temp1 = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp1;

	// row2
	temp1 = state[2][0];
	temp2 = state[2][1];
	state[2][0] = state[2][2];
	state[2][1] = state[2][3];
	state[2][2] = temp1;
	state[2][3] = temp2;

	// row3
	temp1 = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = state[3][0];
	state[3][0] = temp1;
}

void AES::revShiftRows()
{
	byte temp1, temp2;
	// row1
	temp1 = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp1;

	// row2
	temp1 = state[2][0];
	temp2 = state[2][1];
	state[2][0] = state[2][2];
	state[2][1] = state[2][3];
	state[2][2] = temp1;
	state[2][3] = temp2;

	// row3
	temp1 = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp1;
}

void AES::mixCols()
{
	byte c[4][4] = { 0x02, 0x03, 0x01, 0x01,
		0x01, 0x02, 0x03, 0x01,
		0x01, 0x01, 0x02, 0x03,
		0x03, 0x01, 0x01, 0x02 };

	byte b[NK][NB];

	byte temp = 0x00;
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			for (int k = 0; k < NB; ++k)
			{
				temp ^= GFMultiplication(state[k][j], c[i][k]);
			}
			b[i][j] = temp;
			temp = 0x00;
		}
	}

	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			state[i][j] = b[i][j];
		}
	}
}

void AES::revMixCols()
{
	byte c[4][4] = { 0x0E, 0x0B, 0x0D, 0x09,
		0x09, 0x0E, 0x0B, 0x0D,
		0x0D, 0x09, 0x0E, 0x0B,
		0x0B, 0x0D, 0x09, 0x0E };

	byte b[NK][NB];

	byte temp = 0x00;
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			for (int k = 0; k < NB; ++k)
			{
				temp ^= GFMultiplication(state[k][j], c[i][k]);
			}
			b[i][j] = temp;
			temp = 0x00;
		}
	}

	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			state[i][j] = b[i][j];
		}
	}
}

void AES::addRoundKey(int round)
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			state[i][j] ^= key[i][NB*round + j];
		}
	}
}

void AES::printState()
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB; ++j)
		{
			printf_s("%X ", state[i][j]);
		}
		printf_s("\n");
	}
}

void AES::printKey()
{
	for (int i = 0; i < NK; ++i)
	{
		for (int j = 0; j < NB*(NR+1); ++j)
		{
			printf_s("%X ", key[i][j]);
		}
		printf_s("\n");
	}
}

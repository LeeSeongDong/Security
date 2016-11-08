#include "AES.h"

int main()
{
	byte in[16] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p' };
	byte key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	byte out[16];

	AES aes;

	aes.encryption(in, out, key);

	aes.decryption(out, in, key);
	
	system("pause");
	return 0;
}

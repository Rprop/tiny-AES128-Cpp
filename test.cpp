#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifndef CBC
# define CBC   1
#endif // !CBC
#ifndef ECB
# define ECB   0
#endif // !ECB
#ifndef BSIZE
# define BSIZE 4096
#endif // !BSIZE
#ifndef min
# define min(a,b) ((a)<(b)?(a):(b))
#endif // !min

extern "C" {
#include "aes.h"
}

class aes
{
private:
	static short roundup_16(short n)
	{
		return n % 16 == 0 ? n : ((n / 16) + 1) * 16;
	}
	static short str_encode(const char *p, wchar_t o[])
	{
		short l = (short)strlen(p);
		short d = roundup_16((l + 1) * sizeof(wchar_t)); memset(o, 0, d);
		o[0] = (wchar_t)((l << 8) | (l >> 8));
		for (short i = 1; i <= l; ++i) {
			o[i] = (wchar_t)*(p++);
		} //for

		return d;
	}
	static short aes128_encrypt(const char *lpdata, const char *key, char res[])
	{
		const char iv[16] = { 0 };

		wchar_t in_padded[BSIZE];
		short size = str_encode(lpdata, in_padded);

		char key_padded[16] = { 0 };
		memcpy(key_padded, key, strlen(key));

		for (int k = 0; k < size; k += 16) {
			AES128_CBC_encrypt_buffer((uint8_t *)&res[k], &((uint8_t *)in_padded)[k], 16, (const uint8_t *)key_padded, (const uint8_t *)iv);
		} //for

		return size;
	}
	static void aes128_decrypt(const char *lpdata, int size, const char *key, char res[])
	{
		const char iv[16] = { 0 };

		char key_padded[16] = { 0 };
		memcpy(key_padded, key, strlen(key));

		lpdata -= 16;
		short l = -1;
		while ((size -= 16) >= 0) {
			char buffer[16];
			AES128_CBC_decrypt_buffer((uint8_t *)buffer, (uint8_t *)(lpdata += 16), 16, (uint8_t *)key_padded, (uint8_t *)iv);

			short k = 0;
			if (l < 0) {
				l = ((*(short *)buffer << 8) | (*(short *)buffer >> 8));
				++k;
			}
			for (; k < 8; ++k) {
				(res++)[0] = (char)((wchar_t *)&buffer[2 * k])[0];
			} //for
		}
	}

public:
	short size;
	char  buffer[BSIZE];
	char  buffer_str[BSIZE];
	char *encrypt(const char *lpdata, const char *key)
	{
		size = aes128_encrypt(lpdata, key, buffer);
		for (int i = 0; i < size; ++i) {
			sprintf_s(&buffer_str[i * 2], BSIZE - (i * 2), "%.2x", (unsigned char)buffer[i]);
		}

		return buffer_str;
	}
	char *decrypt(const char *lpdata, int size, const char *key)
	{
		aes128_decrypt(lpdata, size, key, buffer_str);

		return buffer_str;
	}
};
 
int main(void)
{
	aes a;
	printf("%s\n", a.encrypt("123", "123"));
	printf("%s\n", a.decrypt(a.buffer, a.size, "123"));


    return 0;
}



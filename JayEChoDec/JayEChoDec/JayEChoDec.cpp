//#pragma comment(lib, "libcrypto.lib")

#include <openssl/des.h>
#include <stdio.h>
#include <Windows.h>
#include <string.h>

#define ENC 1
#define DEC 0

#define SLEN 8


void strtohex(unsigned char *okey, char *str)
{
	char chex[3];
	int hnum = 0x0;
	for (int i = 0; i < SLEN; i++) {
		chex[0] = str[i * 2];
		chex[1] = str[(i * 2) + 1];

		hnum = (int)strtol(chex, NULL, 16); // 16 진수로 변환.. (sizeof(long int) is only 4.)
		okey[i] = hnum;
	}
}

void strtohex_div2(DES_LONG *ctr, char *str)
{
	// 1byte(8) div2 = 4

	char chex[SLEN][3];
	unsigned long lhex[SLEN];
	DES_LONG hnum[2] = { 0x0 };
	for (int i = 0; i < SLEN; i++) {
		chex[i][0] = str[i * 2];
		chex[i][1] = str[(i * 2) + 1];

		lhex[i] = (unsigned long)strtol(chex[i], NULL, 16); // 16 진수로 변환.. (sizeof(long int) is only 4.)
	}

	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 4; j++) {
			hnum[i] += (lhex[(i * 4) + j] << ((3 - j) * 8));
		}
	}

	for (int i = 0; i < 2; i++) {
		ctr[i] = hnum[i];
	}
}

void xoring(DES_LONG *xubject, DES_LONG *plain_or_crypt, DES_LONG *enc_result)
{
	for (int i = 0; i < 2; i++) {
		xubject[i] = plain_or_crypt[i] ^ enc_result[i];
		//printf("plain_or_crypt[%d] = 0x%x | enc_result[%d] = 0x%x \n", i, plain_or_crypt[i], i, enc_result[i]);
		//printf("xubject[%d] = 0x%x\n", i, xubject[i]);
	}
}

bool input_handling(int ac, char **av) {
	// command line arguments exception handling
	if (ac != 5) {
		printf("Please give me 4 arguments :\n");
		printf("./Enc_program [counter_value] [key_value] [plain.txt] [cipher.des]\n");
		printf("An example : \n");
		printf("./Enc_program fecdba9876543210 40fedf386da13d57 plain.txt cipher.des\n");

		return 1;
	}

	// argument str length exception handling
	if (strlen(av[1]) != 16 || strlen(av[2]) != 16) {
		printf("Please give me two strings of 16bytes length. \n");

		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int k;	// be used to know if the key is vaild or not.
	DES_LONG counter[2] = { 0x0, 0x0 };
	unsigned char key[SLEN];
	DES_key_schedule schedule;
	DES_LONG plain_text[2] = { 0x0, 0x0 };
	DES_LONG cipher_result[2] = { 0x0, 0x0 };
	DES_LONG plain_result[2] = { 0x0, 0x0 };
	FILE *fp_des, *fp_result;
	char cipher_tmp_text[17] = { 0 };

	// command line arguments exception handling(1)
	if (input_handling(argc, &argv[0]) == 1) {
		system("pause");
		return 1;
	}

	// file pointers exception handling(2)
	if (fopen_s(&fp_des, argv[3], "r") != 0 || fopen_s(&fp_result, argv[4], "w") != 0) {
		printf("file pointer error!\nPerhaps you don't have a \'%s\'file.\n", argv[3]);
		system("pause");
		return 1;
	}

	// transform these into another variable type
	strtohex_div2(&counter[0], argv[1]); // counter value
	strtohex(&key[0], argv[2]); // key value

	
								// save the cipher text value into a DES_LONG variable.
								// and transform it into another variable type.
	fscanf_s(fp_des, "%s", &cipher_tmp_text[0], sizeof(cipher_tmp_text));
	if (strlen(cipher_tmp_text) != 16) { // exception handling(3)
		printf("Length of the cipher text must be 16bytes.\nprocess terminated.\n");
		printf("strlen(cipher_tmp_text) = %d\n", strlen(cipher_tmp_text));
		system("pause");
		return 1;
	}
	strtohex_div2(&cipher_result[0], &cipher_tmp_text[0]);
	

	// printf("Plain Text : 0x%x, 0x%x \n", plain_text[0], plain_text[1]);
	printf("Counter : 0x%x, 0x%x \n", counter[0], counter[1]);
	printf("Key : ");
	for (int i = 0; i < SLEN; i++) {
		printf("0x%2x ", key[i]);
	}
	printf("\n\n");

	// exception handling(4)
	// check if the key is vaild or not
	if ((k = DES_set_key_checked(&key, &schedule)) != 0) {
		printf("\nkey error : %d \nprocess terminated.\n", k);
		system("pause");
		return 1;
	}

	// counter plus key encription in the CTR mode.
	DES_encrypt1(&counter[0], &schedule, ENC);
	printf("DES Encryption: %x %x\n", counter[0], counter[1]);

	/*
	// xor with the plain text. 
	// therefore, the cipher text is made. 
	xoring(&cipher_result[0], &plain_text[0], &counter[0]); // counter + key
	printf("cipher_result : 0x%x, 0x%x \n", cipher_result[0], cipher_result[1]);
	printf("\n");

	fprintf_s(fp_des, "%x%x", cipher_result[0], cipher_result[1]);
	*/

	//-------------------------------------------------------------------------------------

	//DES_encrypt1(&counter[0], &schedule, DEC);

	xoring(&plain_result[0], &cipher_result[0], &counter[0]); // counter + key
	printf("plain_result : %x %x\n", plain_result[0], plain_result[1]);
	fprintf_s(fp_result, "%x%x", plain_result[0], plain_result[1]);
	system("pause");

	// close all file pointers
	fclose(fp_des);
	fclose(fp_result);

	return 0;
}
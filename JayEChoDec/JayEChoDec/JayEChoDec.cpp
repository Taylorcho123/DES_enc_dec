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

void xoring(DES_LONG *xubject, DES_LONG *plain_or_crypt, DES_LONG *enc_result, int des_length)
{
	int len2_cnt = 0;
	int i;

	for (i = 0; i < des_length; i++, len2_cnt++) {
		if (len2_cnt == 2)
			len2_cnt = 0;

		xubject[i] = plain_or_crypt[i] ^ enc_result[len2_cnt];

		//printf("plain_or_crypt[%d] = 0x%x | enc_result[%d] = 0x%x \n", i, plain_or_crypt[i], len2_cnt, enc_result[len2_cnt]);
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
	DES_LONG *cipher_result;
	DES_LONG *plain_result;
	FILE *fp_des, *fp_result;
	int input_file_size = 0, alloc_size = 0;

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

	//get the input file size
	fseek(fp_des, 0L, SEEK_END);
	input_file_size = ftell(fp_des);
	rewind(fp_des);	// let file pointer go to the front

	// Dynamic allocation of the DES_LONG arrays
	// as the size of the input text
	if (input_file_size % 8 != 0) {
		alloc_size = input_file_size / 8 + 1;
	}
	else {
		alloc_size = input_file_size / 8;
	}
	cipher_result = (DES_LONG *)malloc(sizeof(DES_LONG)*(alloc_size));
	plain_result = (DES_LONG *)malloc(sizeof(DES_LONG)*(alloc_size));

	// save the cipher text value into a DES_LONG variable.
	// and transform it into another variable type.
	printf("Cipher Text : ");
	for (int i = 0; i < alloc_size; i++) {
		fscanf_s(fp_des, "%8x", &cipher_result[i], sizeof(DES_LONG));
		printf("0x%8x ", cipher_result[i]);
	}
	printf("\n");
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

	// xor with the plain text. 
	// therefore, the cipher text is made. 
	xoring(&plain_result[0], &cipher_result[0], &counter[0], alloc_size); // counter + key
	printf("Plain_result : ");
	for (int i = 0; i < alloc_size; i++) {
		fprintf_s(fp_result, "%8x", plain_result[i], sizeof(DES_LONG));
		printf("0x%8x ", plain_result[i]);
	}
	printf("\n");
	
	system("pause");

	// close all file pointers
	fclose(fp_des);
	fclose(fp_result);

	return 0;
}
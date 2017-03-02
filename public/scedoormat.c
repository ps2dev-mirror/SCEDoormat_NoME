#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <inttypes.h>
#include <stdio.h>
#include "scedoormat.h"


void PrintVersion()
{
	printf("\n");
	printf("------------------------------\n");
	printf("| SCEDoormat (No ME Version) |\n");
	printf("| Release 3, 2015/04/13      |\n");
	printf("------------------------------\n");
}


void PrintUsage(char *EXEpath)
{
	printf("\n");
	printf("Usage :\n");
	printf("\n");
	printf("%s INPUT.ELF OUTPUT.KELF KRYPTO.KHN\n", EXEpath);
	printf("\n");
	printf("INPUT.ELF   == The data you want to put in the container\n");
	printf("OUTPUT.KELF == The resulting KELF that will be created\n");
	printf("KRYPTO.KHN  == The SCEDoormat resource file for making the KELF\n");
	printf("\n\n");
	printf("About :\n");
	printf("\n");
	printf("Teh SCEDoormat author would like to thank,\n");
	printf("\"someone who wants to remain anonymous\", l_Oliveira and SP193.\n");
	printf("You Gentlemen know why hehehe...\n");
	printf("\n");
	printf("No, there's no MechaCon emulator or Crabyrighted material in this app.\n");
	printf("That's why it needs a bigass KRYPTO.KHN (pre-encrypted stuff) to work.\n");
	printf("\n");

	system("pause");
}

int main(int argc, char **argv)
{
	int i;

	ReleaseCoDecStruct();

	PrintVersion();

	if(argc == 1 || argc > 4) {
		PrintUsage(argv[0]);
		return -1;
	}


	if(argc == 2) { // Quick & dirty addition for Rev.2. Try to identify KRYPTO.KHN if it's the only input file.
		if(!(INPUT_ELF = fopen(argv[1], "rb"))) {
			printf("Cannot open %s\n", argv[1]);
			return -1;
		}
		fseek(INPUT_ELF, 0, SEEK_END);
		if(ftell(INPUT_ELF) > 0x98) {
			KRYPTO_KHN_PATH = malloc(strlen(argv[1]) * 2);
			memset(KRYPTO_KHN_PATH, 0, strlen(argv[1]) * 2);
			memcpy(KRYPTO_KHN_PATH, argv[1], strlen(argv[1]));
			KRYPTO_KHN = fopen(KRYPTO_KHN_PATH, "rb");
			fseek(KRYPTO_KHN, 0, SEEK_END);
			KRYPTO_KHN_SIZE = ftell(KRYPTO_KHN);
			rewind(KRYPTO_KHN);

			/* Read IDENT and TOC */
			fread(CDS.kHnIDENTkey,	8, 1, KRYPTO_KHN);
			fread(CDS.kHnTOCdata,	8, 1, KRYPTO_KHN);

			/* Setup */
			memcpy(CDS.kHnMAXelfSize,		CDS.kHnTOCdata + 0, 	4);
			memcpy(&kHnMAXelfSize,			CDS.kHnMAXelfSize,  	4);
			//------------------------------
			memcpy(CDS.kHnBlockCount, 		CDS.kHnTOCdata + 4, 	1);
			memcpy(&kHnBlockCount,			CDS.kHnBlockCount,  	1);
			//------------------------------
			memcpy(CDS.kHnHashedBlockCount,	CDS.kHnTOCdata + 5,		1);
			memcpy(&kHnHashedBlockCount,	CDS.kHnHashedBlockCount,1);
			//------------------------------
			memcpy(CDS.kHnDESCsize,			CDS.kHnTOCdata + 6, 	2);
			memcpy(&kHnDESCsize,			CDS.kHnDESCsize, 		2);
			//------------------------------

			if(GetROUNDkey() != 0) {
				close(INPUT_ELF);
				printf("KRYPTO.KHN  == %s\n", argv[1]);
				printf("               (%d bytes)\n", KRYPTO_KHN_SIZE);
				printf("---------------\n\n");
				kHnIdentifier();
				close(KRYPTO_KHN);
				free(KRYPTO_KHN_PATH);
				ReleaseCoDecStruct();
				printf("\n");
				system("pause");
				printf("\n");
				return 1;
			}
			close(KRYPTO_KHN);
			free(KRYPTO_KHN_PATH);
			ReleaseCoDecStruct();
			KRYPTO_KHN_SIZE = 0;
			kHnMAXelfSize = 0;
			kHnBlockCount = 0;
			kHnHashedBlockCount = 0;
			kHnDESCsize = 0;
		}
		close(INPUT_ELF);
		ReleaseCoDecStruct();
	}


	printf("INPUT.ELF   == %s\n", argv[1]);
	if(!(INPUT_ELF = fopen(argv[1], "rb"))) {
		printf("               CAN'T LOAD\n");
		return -1;
	}
	fseek(INPUT_ELF, 0, SEEK_END);
	INPUT_ELF_SIZE = ftell(INPUT_ELF);
	rewind(INPUT_ELF);
	printf("               (%d bytes)\n", INPUT_ELF_SIZE);
	if(INPUT_ELF_SIZE == 0) {
		printf("               CAN'T BE BLANK, FATAL ERROR\n");
		close(INPUT_ELF);
		return -1;
	}
	printf("---------------\n");


	printf("OUTPUT.KELF == ");
	if(argc > 2) {
		OUTPUT_KELF_PATH = malloc(strlen(argv[2]) * 2);
		memset(OUTPUT_KELF_PATH, 0, strlen(argv[2]) * 2);
		memcpy(OUTPUT_KELF_PATH, argv[2], strlen(argv[2]));
	} else {
		OUTPUT_KELF_PATH = malloc(strlen(argv[1]) * 2);
		memset(OUTPUT_KELF_PATH, 0, strlen(argv[1]) * 2);
		memcpy(OUTPUT_KELF_PATH, argv[1], strlen(argv[1]));
		memcpy(OUTPUT_KELF_PATH + strlen(argv[1]), ".kelf\0", 6);
	}
	printf("%s\n", OUTPUT_KELF_PATH);
	if(!(OUTPUT_KELF = fopen(OUTPUT_KELF_PATH, "wb"))) {
		printf("               CAN'T CREATE\n");
		close(INPUT_ELF);
		free(OUTPUT_KELF_PATH);
		return -1;
	}
	printf("               CREATED\n");
	printf("---------------\n");


	printf("KRYPTO.KHN  == ");
	if(argc == 4) {
		KRYPTO_KHN_PATH = malloc(strlen(argv[3]) * 2);
		memset(KRYPTO_KHN_PATH, 0, strlen(argv[3]) * 2);
		memcpy(KRYPTO_KHN_PATH, argv[3], strlen(argv[3]));
	} else {
		KRYPTO_KHN_PATH = malloc(strlen(argv[0]) * 2);
		memset(KRYPTO_KHN_PATH, 0, strlen(argv[0]) * 2);
		memcpy(KRYPTO_KHN_PATH, argv[0], strlen(argv[0]));
		for(i = strlen(KRYPTO_KHN_PATH); i != 0; i--) {
			if(KRYPTO_KHN_PATH[i] == '\\' || KRYPTO_KHN_PATH[i] == '/') {
				memcpy(KRYPTO_KHN_PATH + i + 1, "KRYPTO.KHN\0\0", 12);
				break;
			}
		}
		if(i == 0) {
			memset(KRYPTO_KHN_PATH, 0, strlen(argv[0]) * 2);
			memcpy(KRYPTO_KHN_PATH + i, "KRYPTO.KHN\0\0", 12);
		}
	}
	printf("%s\n", KRYPTO_KHN_PATH);
	if(!(KRYPTO_KHN = fopen(KRYPTO_KHN_PATH, "rb"))) {
		printf("               CAN'T OPEN, FATAL ERROR\n");
		close(INPUT_ELF);
		close(OUTPUT_KELF);
		free(OUTPUT_KELF_PATH);
		free(KRYPTO_KHN_PATH);
		return -1;
	}
	fseek(KRYPTO_KHN, 0, SEEK_END);
	KRYPTO_KHN_SIZE = ftell(KRYPTO_KHN);
	rewind(KRYPTO_KHN);
	printf("               (%d bytes)\n", KRYPTO_KHN_SIZE);
	printf("---------------\n\n");

	if(kHnIdentifier() != 1) {
		close(INPUT_ELF);
		close(OUTPUT_KELF);
		close(KRYPTO_KHN);
		free(OUTPUT_KELF_PATH);
		free(KRYPTO_KHN_PATH);
		ReleaseCoDecStruct();
		return 0;
	}

	if(makeKELF() == 1) printf("Completed :) !\n");

	close(INPUT_ELF);
	close(OUTPUT_KELF);
	close(KRYPTO_KHN);
	free(OUTPUT_KELF_PATH);
	free(KRYPTO_KHN_PATH);
	ReleaseCoDecStruct();

	return 1;
}

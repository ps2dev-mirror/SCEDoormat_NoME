#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <inttypes.h>
#include <stdio.h>
#include "../public/scedoormat.h"


int Round_ELF_Size()
{
	int added_bytes;

	if(precision == 1) return INPUT_ELF_SIZE;


	for(added_bytes = 0; added_bytes < 16; added_bytes++) {
		if(precision == 2 && INPUT_ELF_SIZE % 4  == 0) return INPUT_ELF_SIZE;
		if(precision == 3 && INPUT_ELF_SIZE % 8  == 0) return INPUT_ELF_SIZE;
		if(precision == 4 && INPUT_ELF_SIZE % 16 == 0) return INPUT_ELF_SIZE;
		INPUT_ELF_SIZE++;
	}


	return -666;
}


int Calc_KELF_Quantity()
{
	int divider;

	if(precision == 1) divider = 1;
	if(precision == 2) divider = 4;
	if(precision == 3) divider = 8;
	if(precision == 4) divider = 16;

	int Quantity = (kHnMAXelfSize / divider);

	return Quantity;
}


int Calc_KRYPTO_KHN_Content_Size()
{
	int multiplier = Calc_KELF_Quantity();
	int Content_Size = (0x10 + kHnDESCsize + 0x50 + 0x10 + (kHnHashedBlockCount * 0x08) + ((kHnBlockCount * 0x10) * multiplier));

	return Content_Size;
}

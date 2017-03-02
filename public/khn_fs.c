#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <inttypes.h>
#include <stdio.h>
#include "../public/scedoormat.h"


/*********************************************************************************************
void ReleaseCoDecStruct();
Releases the entire CoDecStuff struct
*********************************************************************************************/
void ReleaseCoDecStruct()
{
	memset((void *)&CDS, 0, sizeof(struct CoDecStuff));
}

/*********************************************************************************************
void ClearCoDecBuffer();
Clears the temporary CoDec buffer (which is uint8_t data[0x10000]; in the CoDecStuff struct)
*********************************************************************************************/
void ClearCoDecBuffer()
{
	memset(CDS.data, 0, 0x10000);
}

/*********************************************************************************************
void CoDec(char *inbuf, int segment_length);
Decrypts/Encrypts a segment of KRYPTO.KHN.
Before you use it, you have to identify the kHnIDENTkey and set the correct kHnROUNDkey
*********************************************************************************************/
void CoDec(unsigned char *inbuf, int segment_length)
{
	int i;

	for(i = 0; i < segment_length; i+=8) {
		if(i + 0 < segment_length) CDS.data[i+0] = (inbuf[i+0] ^ CDS.kHnROUNDkey[0]);
		if(i + 1 < segment_length) CDS.data[i+1] = (inbuf[i+1] ^ CDS.kHnROUNDkey[1]);
		if(i + 2 < segment_length) CDS.data[i+2] = (inbuf[i+2] ^ CDS.kHnROUNDkey[2]);
		if(i + 3 < segment_length) CDS.data[i+3] = (inbuf[i+3] ^ CDS.kHnROUNDkey[3]);
		if(i + 4 < segment_length) CDS.data[i+4] = (inbuf[i+4] ^ CDS.kHnROUNDkey[4]);
		if(i + 5 < segment_length) CDS.data[i+5] = (inbuf[i+5] ^ CDS.kHnROUNDkey[5]);
		if(i + 6 < segment_length) CDS.data[i+6] = (inbuf[i+6] ^ CDS.kHnROUNDkey[6]);
		if(i + 7 < segment_length) CDS.data[i+7] = (inbuf[i+7] ^ CDS.kHnROUNDkey[7]);
	}
}

/*********************************************************************************************
int DnasloadPSXCheck();
Check if the PS2 KELF is tolerated by the PSX
Returns 0 if nope,
Returns 1 if yep.
Before you use this function, the KELF header has to be loaded in CDS.data
*********************************************************************************************/
int DnasloadPSXCheck()
{
	if(CDS.data[22] == 0x00 && (CDS.data[28] & (1 << 0))) {
		if(CDS.data[23] == 0x0B) { // Dnas_WithHDD
			if(CDS.data[0]  == 0x01 && CDS.data[1]  == 0x00 && CDS.data[2]  == 0x00 && CDS.data[3]  == 0x04 &&
			   CDS.data[4]  == 0x00 && CDS.data[5]  == 0x06 &&
			   CDS.data[8]  == 0x00 && CDS.data[9]  == 0x0E &&                         CDS.data[11] == 0x00 &&
			   CDS.data[12] == 0x00 && CDS.data[13] == 0x00 && CDS.data[14] == 0x00                           ) {           // User Header
			if(CDS.data[6]  == 0x00 && CDS.data[7]  == 0x4A && CDS.data[10] == 0x01 && CDS.data[15] == 0x02) return 1;      // JPN
			else if(CDS.data[6]  == 0x01 && CDS.data[7]  == 0x55 && CDS.data[10] == 0x02 && CDS.data[15] == 0x06) return 1; // USA
			else return 0; // PSBBN stuff, unknown... Treat as not PSX allowed.
			}
		}
		if(CDS.data[23] == 0x01) { // SYSTEM flagged JPN POL
			if(CDS.data[0]  == 0x01 && CDS.data[1]  == 0x00 && CDS.data[2]  == 0x00 && CDS.data[3]  == 0x04 &&
			   CDS.data[4]  == 0x00 && CDS.data[5]  == 0x02 && CDS.data[6]  == 0x00 && CDS.data[7]  == 0x4A &&
			   CDS.data[8]  == 0x00 && CDS.data[9]  == 0x0B && CDS.data[10] == 0x01 && CDS.data[11] == 0x00 &&
			   CDS.data[12] == 0x00 && CDS.data[13] == 0x00 && CDS.data[14] == 0x00 && CDS.data[15] == 0x3C)
			return 1;
			else return 0; // Common stuff, unknown... Treat as not PSX allowed.
		}
	}

	return 0;
}

/*********************************************************************************************
int StupidSys2x6Check();
The criterias for triggering this shit are very weak. I should use a MG header hashes bank next time...
*********************************************************************************************/
int StupidSys2x6Check()
{
	if(CDS.data[0]  == 0x01 && CDS.data[1]  == 0x00 && CDS.data[2]  == 0x00 && CDS.data[3]  == 0x00 &&
	   CDS.data[4]  == 0x02 && CDS.data[5]  == 0x00 && CDS.data[6]  == 0x00 && CDS.data[7]  == 0x00 &&
	   CDS.data[8]  == 0x03 && CDS.data[9]  == 0x00 && CDS.data[10] == 0x00 && CDS.data[11] == 0x00 &&
	   CDS.data[12] == 0x04 && CDS.data[13] == 0x00 && CDS.data[14] == 0x00 && CDS.data[15] == 0x00 &&
	   CDS.data[18] == 0x00 && CDS.data[20] == 0x40 && CDS.data[21] == 0x01 && CDS.data[22] == 0x00 &&
	   CDS.data[23] == 0x07 && CDS.data[24] == 0x2C && CDS.data[25] == 0x02 && CDS.data[28] == 0x03)
	   return 1;

	return 0;
}

/*********************************************************************************************
int UserHeaderMechaBanStatus();
Checks if the KELF has the DVD Player 1.00 user header (which is theorically MechaCon blacklisted).
D0 D8 CA D8  BA BD B1 A5  BA BD B1 A5  E4 F8 B9 B8
                                       -- --
Returns 0 if not blacklisted (the entire DVD Player 1.00 user header was not found),
Returns 1 if the entire DVD Player 1.00 user header was found,
Returns 2 if suspicious (I can't verify that it's actually banned),

Before you use this function, the KELF header has to be loaded in CDS.data
*********************************************************************************************/
int UserHeaderMechaBanStatus()
{
	if(CDS.data[0]  == 0xD0 && CDS.data[1]  == 0xD8 && CDS.data[2]  == 0xCA && CDS.data[3]  == 0xD8 &&
	   CDS.data[4]  == 0xBA && CDS.data[5]  == 0xBD && CDS.data[6]  == 0xB1 && CDS.data[7]  == 0xA5 &&
	   CDS.data[8]  == 0xBA && CDS.data[9]  == 0xBD && CDS.data[10] == 0xB1 && CDS.data[11] == 0xA5 &&
	   CDS.data[12] == 0xE4 && CDS.data[13] == 0xF8 && CDS.data[14] == 0xB9 && CDS.data[15] == 0xB8)
	   return 1; // The whole user header
	if(CDS.data[12] == 0xE4 || CDS.data[13] == 0xF8)
	   return 2; // Suspicious shit here man

	return 0; // All OK.
}

/*********************************************************************************************
int GetROUNDkey();
Determines and sets the correct kHnROUNDkey, and the precision rate
kHnIDENTkey MUST BE LOADED in the CoDecStuff struct
Returns the precision value if success
Returns zero if failure
*********************************************************************************************/
int GetROUNDkey()
{
	ClearCoDecBuffer();

	/* Test kHn_Round_to_00 */
	precision = 1;
	memcpy(CDS.kHnROUNDkey,	kHn_Round_to_00, 8);
	CoDec(CDS.kHnIDENTkey, 8);
	if(memcmp(CDS.kHnTOCdata, CDS.data, 8) == 0) {
		ClearCoDecBuffer();
		return precision;
	}
	ClearCoDecBuffer();

	/* Test kHn_Round_to_04 */
	precision = 2;
	memcpy(CDS.kHnROUNDkey,	kHn_Round_to_04, 8);
	CoDec(CDS.kHnIDENTkey, 8);
	if(memcmp(CDS.kHnTOCdata, CDS.data, 8) == 0) {
		ClearCoDecBuffer();
		return precision;
	}
	ClearCoDecBuffer();

	/* Test kHn_Round_to_08 */
	precision = 3;
	memcpy(CDS.kHnROUNDkey,	kHn_Round_to_08, 8);
	CoDec(CDS.kHnIDENTkey, 8);
	if(memcmp(CDS.kHnTOCdata, CDS.data, 8) == 0) {
		ClearCoDecBuffer();
		return precision;
	}
	ClearCoDecBuffer();

	/* Test kHn_Round_to_16 */
	precision = 4;
	memcpy(CDS.kHnROUNDkey,	kHn_Round_to_16, 8);
	CoDec(CDS.kHnIDENTkey, 8);
	if(memcmp(CDS.kHnTOCdata, CDS.data, 8) == 0) {
		ClearCoDecBuffer();
		return precision;
	}
	ClearCoDecBuffer();


	return 0;
}


/*********************************************************************************************
int kHnIdentifier(FILE *KRYPTO_KHN);
Releases and renews the CoDecStuff struct
Gets and prints all the infos about KRYPTO.KHN
*********************************************************************************************/
int kHnIdentifier()
{
	int i;


	/* Prepare */
	ReleaseCoDecStruct();
	rewind(KRYPTO_KHN);

	/* Minimal filesize check */
	if(KRYPTO_KHN_SIZE < 0x98) { // WTF seriously ?
		printf("\n** FATAL ERROR **\n");
		printf("KRYPTO.KHN is too small (WTF ?)\n");
		return 0;
	}

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

	/* Get the deobfuscation key and set the precision rate */
	if(GetROUNDkey() == 0) {
		printf("\n** FATAL ERROR **\n");
		printf("Unable to identify the contents of KRYPTO.KHN\n");
		printf("Its version is not supported or the file is damaged...\n");
		return 0;
	}

	/* Maximal filesize check */
	if(Calc_KRYPTO_KHN_Content_Size() != KRYPTO_KHN_SIZE) { // Truncated ? Too big ? Terminate.
		printf("\n** FATAL ERROR **\n");
		printf("KRYPTO.KHN is corrupted\n");
		printf("Filesize (%d bytes) != Content size (%d bytes)\n", KRYPTO_KHN_SIZE, Calc_KRYPTO_KHN_Content_Size());
		return 0;
	}

	/* Read and print the file description */
	if(kHnDESCsize != 0) { // Only if there's one.
		printf("\nAbout KRYPTO.KHN :\n");
		fread(CDS.data, kHnDESCsize, 1, KRYPTO_KHN);
		CoDec(CDS.data, kHnDESCsize);
		printf("%s\n", CDS.data);
		ClearCoDecBuffer();
	}

	/* Read the KELF User Header and the MG Header */
	fread(CDS.data, 0x20, 1, KRYPTO_KHN);
	CoDec(CDS.data, 0x20);
	i = Calc_KELF_Quantity();

	/* Because this stupid KRYPTO.KHN has the Bit data of a zero sized block and the Bit data for a kHnMAXelfSize sized block is NOT in KRYPTO.KHN, substract one */
	i--;
	if(precision == 1) kHnMAXelfSize -= precision; // That ridiculous thing was made like that to workaround the AVAST!'s false-positive virus alert about Win32:Evo-gen :facepalm:
	if(precision == 2) kHnMAXelfSize -= 4;
	if(precision == 3) kHnMAXelfSize -= precision + 5; // F*ck AVAST!, f*ck that pile of garbage already !
	if(precision == 4) kHnMAXelfSize -= 16;
	/* End of substraction */

	printf("\nKRYPTO.KHN properties :\n");
	printf("Maximum Capacity of the Container     == %d bytes (%Xh)\n", kHnMAXelfSize, kHnMAXelfSize); // The user's INPUT.ELF must NOT be larger
	//------------------------------
	printf("Precision Rate for Embedding Contents == %d ", precision);
	if(precision == 1) printf("(BEST)\n");
	if(precision == 2) printf("(GOOD, round length to multiple of 4)\n");
	if(precision == 3) printf("(SUCKS, round length to multiple of 8)\n");
	if(precision == 4) printf("(WORST, round length to multiple of 16)\n");
	//------------------------------
	printf("KELF Quantity                         == %d\n", i); // The number of KELFs contained by KRYPTO.KHN. We got it using Calc_KELF_Quantity();
	//------------------------------
	printf("Length of the KELF Header             == %d bytes (0x%02X%02X)\n", (CDS.data[21] * 10) + CDS.data[20], CDS.data[21], CDS.data[20]);
	//------------------------------
	printf("Hashed Blocks Quantity                == %d\n",       kHnHashedBlockCount);
	//------------------------------
	printf("Total Length of the MG Hashed Blocks  == %d bytes\n", kHnHashedBlockCount * 8);
	//------------------------------

	if(StupidSys2x6Check() == 0) {
		printf("\nKryptoELF specs :\n");
		i = UserHeaderMechaBanStatus();
		printf("User Header is MechaCon Blacklisted   == ");
		if(i == 0) printf("False\n");
		if(i == 1) printf("True\n");
		if(i == 2) printf("Unknown\n");
		//------------------------------
		printf("Is a HDD Master Boot Record Container == ");
		if(CDS.data[0] == 0x01 && CDS.data[3] == 0x04) printf("True\n");
		else printf("False (User Header Starts With %02X %02X %02X %02X)\n",CDS.data[0],CDS.data[1],CDS.data[2],CDS.data[3]);
		//------------------------------
		printf("Target Machine Type                   == ");
		i = DnasloadPSXCheck();
		if(CDS.data[22] == 0x00 && (CDS.data[23] == 0x05 || CDS.data[23] == 0x07))				printf("PS2 (CEX Only)\n");
		else if(CDS.data[22] == 0x00 && CDS.data[23] != 0x05 && CDS.data[23] != 0x07 && i == 0)	printf("PS2 (CEX & DEX)\n");
		else if(CDS.data[22] == 0x00 && CDS.data[23] != 0x05 && CDS.data[23] != 0x07 && i == 1)	printf("PS2 (CEX & DEX) + PSX\n");
		else if(CDS.data[22] == 0x01)									printf("PSX\n");
		else 															printf("Unknown (0x%02X)\n", CDS.data[22]);
		//------------------------------
		printf("Target Application Type               == ");
		if(CDS.data[23] == 0x00)		printf("UPGRADE\n"); // As seen in system upgrade packages (aka "wobbles") of utility discs
		else if(CDS.data[23] == 0x01)	printf("SYSTEM\n"); // Common
		else if(CDS.data[23] == 0x05)	printf("DVDPLAYER KIRX\n"); // As seen in DVD Player update KIRXs. The MechaCon invokation flag is 0x021C in this kind of container.
		else if(CDS.data[23] == 0x07)	printf("DVDPLAYER\n"); // The infamous flag which allows DVDV playback. The decryption of such KELF is denied by the TEST MechaCon.
		else if(CDS.data[23] == 0x0B)	printf("Dnas_WithHDD\n"); // As seen in DNASLOAD containers, PSBBN KELFs...
		else 							printf("Unknown (0x%02X)\n", CDS.data[23]);
		//------------------------------
		printf("M@gicGate Zones                       == ");
		for(i = 0; i < 8; i++) {
			if(i != 0) printf("+");
			if(CDS.data[28] & (1 << i)) printf("%s", KELF_MG_Zones[i]);
		}
		printf("\n");
		//------------------------------
	} else {
		printf("\n** FATAL ERROR **\n");
		printf("KRYPTO.KHN seems to contain COH stuff...\n");
		printf("Can't proceed, since there's no implementation for such thing.\n");
		printf("Not a COH/System2#6 KRYPTO.KHN ? Then it's a bug. Please contact kHn.\n");
		return 0;
	}

	ClearCoDecBuffer();
	rewind(KRYPTO_KHN);

	return 1;
}


int makeKELF() {

	int DataPos;
	int original_ELF_size = INPUT_ELF_SIZE;

	ClearCoDecBuffer();

	if(Round_ELF_Size() < 0) {
		printf("\n** FATAL ERROR **\n");
		printf("Unexpected Round_ELF_Size() failure\n");
		printf("Please contact kHn\n");
		return 0;
	}

	if(INPUT_ELF_SIZE > kHnMAXelfSize) {
		printf("\n** FATAL ERROR **\n");
		printf("Your input ELF is too big\n");
		return 0;
	}

	printf("\nWriting the output KELF");

	/* Write the KELF header + 8 first bytes of the Bit Table */
	DataPos = 16 + kHnDESCsize;				// After the KRYPTO.KHN header, after the KRYPTO.KHN description
	fseek(KRYPTO_KHN, DataPos, SEEK_SET);	// Seek to the KELF start (Skip the KRYPTO.KHN header, skip the KRYPTO.KHN description)
	printf(".");
	fread(CDS.data, 80, 1, KRYPTO_KHN);		// Read the stuff (80 bytes == User Header + MG Header + Hash + Kbit + Kc + 8 first bytes of the Bit Table)
	printf(".");
	CoDec(CDS.data, 80);					// Deobfuscate the buffered stuff
	fwrite(CDS.data, 80, 1, OUTPUT_KELF);	// Write the deobfuscated stuff
	ClearCoDecBuffer();
	printf(".");

	/* Write the rest of the Bit Table */
	DataPos = 16 + kHnDESCsize + 80 + 16 + (kHnHashedBlockCount * 8);
	if(precision == 1) DataPos += (INPUT_ELF_SIZE / 1)  * (kHnBlockCount * 16);
	if(precision == 2) DataPos += (INPUT_ELF_SIZE / 4)  * (kHnBlockCount * 16);
	if(precision == 3) DataPos += (INPUT_ELF_SIZE / 8)  * (kHnBlockCount * 16);
	if(precision == 4) DataPos += (INPUT_ELF_SIZE / 16) * (kHnBlockCount * 16);

	fseek(KRYPTO_KHN, DataPos, SEEK_SET);					// Seek to the Bit data
	printf(".");
	fread(CDS.data, kHnBlockCount * 16, 1, KRYPTO_KHN);		// Read the stuff
	printf(".");
	CoDec(CDS.data, kHnBlockCount * 16);					// Deobfuscate the buffered stuff
	fwrite(CDS.data, kHnBlockCount * 16, 1, OUTPUT_KELF);	// Write the deobfuscated stuff
	ClearCoDecBuffer();
	printf(".");

	/* Write the two last hashes of the KELF header */
	DataPos = 16 + kHnDESCsize + 80;
	fseek(KRYPTO_KHN, DataPos, SEEK_SET);
	printf(".");
	fread(CDS.data, 16, 1, KRYPTO_KHN);
	printf(".");
	CoDec(CDS.data, 16);
	fwrite(CDS.data, 16, 1, OUTPUT_KELF);
	ClearCoDecBuffer();

	/* Write the input ELF into the KELF container */
	rewind(INPUT_ELF);
	for(DataPos = 0; DataPos < original_ELF_size; DataPos += 0x10000) {
		if(DataPos + 0x10000 >= original_ELF_size) {
			printf(".");
			fread(CDS.data, 0x10000 - (DataPos + 0x10000 - original_ELF_size), 1, INPUT_ELF);
			fwrite(CDS.data, 0x10000 - (DataPos + 0x10000 - original_ELF_size), 1, OUTPUT_KELF);
			ClearCoDecBuffer();
		} else {
			printf(".");
			fread(CDS.data, 0x10000, 1, INPUT_ELF);
			fwrite(CDS.data, 0x10000, 1, OUTPUT_KELF);
			ClearCoDecBuffer();
		}
	}
	if(precision != 1 && original_ELF_size != INPUT_ELF_SIZE) fwrite(CDS.data, INPUT_ELF_SIZE - original_ELF_size, 1, OUTPUT_KELF); // PADDING

	/* Write the encrypted/hashed M@gicGate blocks */
	DataPos = 16 + kHnDESCsize + 80 + 16;
	fseek(KRYPTO_KHN, DataPos, SEEK_SET);
	printf(".");
	fread(CDS.data, kHnHashedBlockCount * 8, 1, KRYPTO_KHN);
	printf(".");
	CoDec(CDS.data, kHnHashedBlockCount * 8);
	fwrite(CDS.data, kHnHashedBlockCount * 8, 1, OUTPUT_KELF);
	ClearCoDecBuffer();
	printf(".\n");

	return 1;
}

struct CoDecStuff {
	uint8_t kHnROUNDkey[8];
	uint8_t data[0x10000];
	uint8_t kHnIDENTkey[8];			// KRYPTO_KHN[00]+KRYPTO_KHN[01]+KRYPTO_KHN[02]+KRYPTO_KHN[03]+KRYPTO_KHN[04]+KRYPTO_KHN[05]+KRYPTO_KHN[06]+KRYPTO_KHN[07]
	uint8_t kHnTOCdata[8];			// KRYPTO_KHN[08]+KRYPTO_KHN[09]+KRYPTO_KHN[10]+KRYPTO_KHN[11]+KRYPTO_KHN[12]+KRYPTO_KHN[13]+KRYPTO_KHN[14]+KRYPTO_KHN[15]
	uint8_t kHnMAXelfSize[4];		// KRYPTO_KHN[08]+KRYPTO_KHN[09]+KRYPTO_KHN[10]+KRYPTO_KHN[11]
	uint8_t kHnBlockCount[1];		// KRYPTO_KHN[12]
	uint8_t kHnHashedBlockCount[1];	// KRYPTO_KHN[13]
	uint8_t kHnDESCsize[2];			// KRYPTO_KHN[14]+KRYPTO_KHN[15]
} __attribute__((packed));

struct CoDecStuff CDS;				// CoDec context control

FILE *KRYPTO_KHN;
int KRYPTO_KHN_SIZE;

FILE *INPUT_ELF;
FILE *OUTPUT_KELF;

char *OUTPUT_KELF_PATH;
char *KRYPTO_KHN_PATH;

int INPUT_ELF_SIZE;
int OUTPUT_KELF_SIZE;

/* Used for Maths */
int kHnMAXelfSize;
int kHnBlockCount;
int kHnHashedBlockCount;
int kHnDESCsize;

int precision;						// Precision rate. See kHn_Round_to_## keys below


static uint8_t kHn_Round_to_00[8] = { 0x72, 0x16, 0x09, 0x94, 0x63, 0xA5, 0xF9, 0x87 };	// The block length is the true content size	(precision == 1 == BEST)
static uint8_t kHn_Round_to_04[8] = { 0x12, 0xFD, 0x55, 0x7F, 0x05, 0x8B, 0xB0, 0x0B };	// Round the block length to multiple of 4		(precision == 2 == GOOD)
static uint8_t kHn_Round_to_08[8] = { 0xE2, 0xA8, 0x66, 0xF0, 0x75, 0xB1, 0x40, 0x86 };	// Round the block length to multiple of 8		(precision == 3 == SUCKS)
static uint8_t kHn_Round_to_16[8] = { 0x55, 0xA0, 0x92, 0xBC, 0x34, 0x01, 0x9A, 0x1D };	// Round the block length to multiple of 16		(precision == 4 == WORST)

static char *KELF_MG_Zones[8] = {"Japan", "USA", "Europe", "Oceania", "Asia", "Russia", "China", "Mexico"};

/* khn_fs.c */
void ReleaseCoDecStruct();
void ClearCoDecBuffer();
void CoDec(unsigned char *inbuf, int segment_length);
int DnasloadPSXCheck();
int StupidSys2x6Check();
int UserHeaderMechaBanStatus();
int GetROUNDkey();
int kHnIdentifier();
int makeKELF();

/* khn_maths.c */
int Round_ELF_Size();
int Calc_KELF_Quantity();
int Calc_KRYPTO_KHN_Content_Size();

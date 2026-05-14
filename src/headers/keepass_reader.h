#ifndef KEEPASS_READER
#define KEEPASS_READER

#include <stdint.h>
#include <stdio.h>

#define FILE_SIGNATURE_VALIDATION 0x9AA2D903

enum file_version
{
  KDB      = 0xB54BFB65,
  PRE_KDBX = 0xB54BFB66,
  KDBX     = 0xB54BFB67l,

  VARIANT_DICT_CURRENT = 0x0100
};

enum type
{
  END_OF_HEADER          = 0x0,
  COMMENT                = 0x1,
  CYPHER_ID              = 0x2,
  COMPRESSIONS_FLAGS     = 0x3,
  MASTER_SEED            = 0x4,
  TRANSFORM_SEED         = 0x6,
  ENCRYPTION_IV          = 0x7,
  PROTECTED_STREAM_EY    = 0x8,
  STREAM_START_BYTES     = 0x9,
  INNER_RANDOM_STREAM_ID = 0xA,
  KDF_PARAMETER          = 0xB,
  T_UNKNOWN
};

enum COMPRESSION_ALGORITHM
{
  AES256 = 0,
  CHACHA20,
  UNKNOWN
};

enum VALUE_TYPE
{
  UINT32 = 0x04,
  UINT64 = 0x05,
  BOOL   = 0x08,
  INT32  = 0x0C,
  INT64  = 0x0D,
  STR    = 0x18,
  BYTE   = 0x42
};

typedef struct
{
  unsigned char type;
  uint32_t name_size;
  unsigned char* name;
  uint32_t value_size;
  unsigned char* value;
} variant_dictionnary;

typedef struct
{
  variant_dictionnary* dictionnary;
  size_t len;
  size_t capacity;
} v_dictarray;

typedef struct
{
  unsigned char* array;
  size_t len;
} bytearray;

typedef struct
{
  enum COMPRESSION_ALGORITHM compression_algorithm;
  size_t compression_flag;
  bytearray* seed;
  bytearray* nonce;
  bytearray* kdf_parameter;

  // Computed in read_header function
  bytearray* _key;
} header;

static const unsigned char AES_256_CIPHER[16] = {
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
    0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF};

static const unsigned char CHACHA20_CIPHER[16] = {
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5,
    0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A};

static const unsigned char EOH[4] = {0xD, 0xA, 0xD, 0xA};

static const unsigned char KDF_NAME_UUID[5] = {0x24, 0x55, 0x55, 0x49, 0x44};
static const unsigned char KDF_NAME_I[1]    = {0x49};
static const unsigned char KDF_NAME_M[1]    = {0x4D};
static const unsigned char KDF_NAME_P[1]    = {0x50};
static const unsigned char KDF_NAME_R[1]    = {0x52};
static const unsigned char KDF_NAME_S[1]    = {0x53};
static const unsigned char KDF_NAME_V[1]    = {0x56};

static const unsigned char AES_KDF[16]  = {0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A,
                                           0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08,
                                           0xC1, 0x8A, 0x4F, 0xEA};
static const unsigned char ARGON2D[16]  = {0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29,
                                           0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4,
                                           0x03, 0xE3, 0x0A, 0x0C};
static const unsigned char ARGON2DI[16] = {0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB,
                                           0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E,
                                           0xC6, 0xF0, 0xA1, 0xE6};

typedef struct
{
  bytearray* name;
  bytearray* value;
} KDF_Parameter;

typedef struct
{
  uint8_t UUID[16];
  KDF_Parameter* parameters;
  size_t len;
} KDF;

// utils
void bytearray_init(bytearray** array, unsigned char* content, size_t length);
void bytearray_free(bytearray* array);
void free_header(header* header);
void free_dictarray(v_dictarray* dictarray);
KDF* make_KDF(v_dictarray* dictarray);
bytearray* KDF_getParameter(KDF* kdf, unsigned char* name, size_t n);
void free_KDF(KDF* kdf);

header* read_header(FILE* file);
#endif

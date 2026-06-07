// References: https://keepass.info/help/kb/kdbx.html

#include "keepass_reader.h"
#include "macros.h"
#include <argon2.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

header* read_keepass_header(FILE* file)
{
  enum type type = T_UNKNOWN;
  size_t length;
  size_t major_minor_version;
  fread(&major_minor_version, 4, 1, file);
  if (major_minor_version != 0x00040000)
    ERROR("Major/minor version of file not implemented. Supported keepass "
          "version: 4.0");
  unsigned char* content;
  header* h = malloc(sizeof(header));
  if (!h) ERROR("Failed to allocate memory for h");
  h->seed          = NULL;
  h->nonce         = NULL;
  h->kdf_parameter = NULL;

  while (type != END_OF_HEADER)
  {
    fread(&type, 1, 1, file);
    fread(&length, 4, 1, file);
    content = malloc(length);
    fread(content, length, 1, file);
    switch (type)
    {
    case CYPHER_ID:
      h->compression_algorithm = UNKNOWN;
      if (!memcmp(content, AES_256_CIPHER, length))
        h->compression_algorithm = AES256;
      if (!memcmp(content, CHACHA20_CIPHER, length))
        h->compression_algorithm = CHACHA20;
      break;
    case COMPRESSIONS_FLAGS:
      memcpy(&h->compression_flag, content, length);
      break;
    case MASTER_SEED:
    case ENCRYPTION_IV:
    case KDF_PARAMETER:
    {
      bytearray** elem =
          type == MASTER_SEED
              ? &h->seed
              : (type == ENCRYPTION_IV ? &h->nonce : &h->kdf_parameter);
      bytearray_init(elem, content, length);
      break;
    }
    case END_OF_HEADER:
      if (memcmp(content, EOH, length)) ERROR("Bad value for end of header");
      break;
    default: break;
    }
    free(content);
  }

  return h;
}

header* read_header(FILE* file)
{
  size_t fs;
  enum file_version fv;
  fread(&fs, 4, 1, file);
  if (fs != FILE_SIGNATURE_VALIDATION) ERROR("Not a keepass file");
  fread(&fv, 4, 1, file);
  header* h;
  switch (fv)
  {
  case KDB: ERROR("Not implemented"); break;
  case PRE_KDBX: ERROR("Not implemented"); break;
  case KDBX: h = read_keepass_header(file); break;
  default: ERROR("Not a valid version");
  }

  // KDF
  bytearray* _KDF = h->kdf_parameter;
  h->kdf          = read_variant_dictionary(_KDF);
  return h;
}

keys* compute_keys(header* header)
{
  keys* k = malloc(sizeof(keys));
  // Master password
  unsigned char password[13] = "elioleplusbo";
  unsigned char* R           = malloc(SHA256_DIGEST_LENGTH);
  unsigned char* T           = malloc(32);
  MCHK(R);
  MCHK(T);
  SHA256(password, 12, R);

  // R is the SHA-256 of
  // - SHA-256 hash of pwd
  // -...
  // so there is 2 SHA256
  SHA256(R, 32, R);

  uint64_t t_cost, m_cost, parallelism;

  bytearray *t_cost_array, *m_cost_array, *parallelism_array, *salt_array;
  // Key derivation (Only ARGON2D is implemented yet)
  if (!memcmp(&header->kdf->UUID, ARGON2D, 16))
  {

    t_cost_array = KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_I, 1);
    memcpy(&t_cost, t_cost_array->array, t_cost_array->len);
    m_cost_array = KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_M, 1);
    memcpy(&m_cost, m_cost_array->array, m_cost_array->len);
    parallelism_array =
        KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_P, 1);
    memcpy(&parallelism, parallelism_array->array, parallelism_array->len);
    salt_array = KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_S, 1);
    argon2d_hash_raw(t_cost, m_cost / 1024, parallelism, R,
                     SHA256_DIGEST_LENGTH, salt_array->array, salt_array->len,
                     T, 32);
  }

  unsigned char* STx01 = malloc(header->seed->len + 33);
  memcpy(STx01, header->seed->array, header->seed->len);
  memcpy(STx01 + header->seed->len, T, 32);
  STx01[header->seed->len + 32] = 0x01;

  //  Compute master key
  SHA256(STx01, header->seed->len + 32, k->master_key);

  // Compute HMAC-SHA-256 header hash key
  unsigned char tohash[72];
  memset(tohash, 0xFF, 8);

  SHA512(STx01, header->seed->len + 33, k->hashed_STx01);

  memcpy(tohash + 8, k->hashed_STx01, 64);
  SHA512(tohash, 72, k->hmac_header_key);

  FREE(R);
  FREE(T);
  FREE(STx01);
  return k;
}

// -1: Integrity/Autenticity failed
// otherwise, returns bool value representing if we need to stop
int compute_block(FILE* f, keys* k, uint64_t index)
{
  unsigned char hash[32], chash[32], *block, *to_hash, *hmac_key;

  uint32_t size;

  fread(hash, 32, 1, f);
  fread(&size, sizeof(uint32_t), 1, f);
  if (!size) return !size;
  block = malloc(size);
  fread(block, size, 1, f);

  // Integrity/Authenticity Check
  MCHK((to_hash = malloc(sizeof(uint64_t) + sizeof(uint32_t) + size)))
  memcpy(to_hash, &index, sizeof(uint64_t));
  memcpy(to_hash + sizeof(uint64_t), &size, sizeof(uint32_t));
  memcpy(to_hash + sizeof(uint64_t) + sizeof(uint32_t), block, size);

  hmac_key = HMAC_SHA_256_HASH_KEY(k, index);
  HMAC(EVP_sha256(), hmac_key, 64, to_hash,
       sizeof(uint64_t) + sizeof(uint32_t) + size, chash, NULL);
  free(hmac_key);

  if (memcmp(chash, hash, 32))
  {
    fprintf(stderr,
            "Failed to validate %lu data block: the file is corrupted.\n",
            index);
    free(block);
    free(to_hash);
    return -1;
  }
  free(block);
  free(to_hash);
  return 1;
}

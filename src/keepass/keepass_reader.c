// References: https://keepass.info/help/kb/kdbx.html

#include "keepass_reader.h"
#include "macros.h"
#include <argon2.h>
#include <openssl/sha.h>
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

v_dictarray* read_variant_dictionnary(bytearray* array)
{
  size_t index = 2, version;
  memcpy(&version, array->array, 2);
  v_dictarray* dictarray = malloc(sizeof(v_dictarray));
  variant_dictionnary* dict;
  MCHK(dictarray);
  dictarray->len         = 0;
  dictarray->capacity    = 1;
  dictarray->dictionnary = malloc(sizeof(variant_dictionnary));
  MCHK(dictarray->dictionnary);
  if (version != VARIANT_DICT_CURRENT)
    ERROR("Failed to check version of variant dictionnary ");
  // Items
  while (array->array[index])
  {
    // List reallocation
    if (dictarray->capacity == dictarray->len)
    {
      dictarray->capacity *= 2;
      dictarray->dictionnary =
          realloc(dictarray->dictionnary,
                  dictarray->capacity * sizeof(variant_dictionnary));
    }
    dict       = &dictarray->dictionnary[dictarray->len];
    dict->type = array->array[index];
    index++;
    memcpy(&(dict->name_size), &array->array[index], 4);
    index += 4;
    dict->name = malloc(dict->name_size);
    MCHK(dict->name);
    memcpy(dict->name, &array->array[index], dict->name_size);
    index += dict->name_size;
    memcpy(&(dict->value_size), &array->array[index], 4);
    index += 4;
    dict->value = malloc(dict->value_size);
    MCHK(dict->value);
    memcpy(dict->value, &array->array[index], dict->value_size);
    index += dict->value_size;
    dictarray->len++;
  }

  return dictarray;
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
  bytearray* _KDF        = h->kdf_parameter;
  v_dictarray* dictarray = read_variant_dictionnary(_KDF);
  KDF* kdf               = make_KDF(dictarray);

  // Key computation

  // Master password
  unsigned char password[13] = "elioleplusbo";
  unsigned char* R           = malloc(SHA256_DIGEST_LENGTH);
  unsigned char* T           = malloc(
      32); // Why 32 ? Good question, seems to be the default value to set.
  unsigned char* key  = malloc(SHA256_DIGEST_LENGTH);
  unsigned char* _key = malloc(h->seed->len + 32);
  MCHK(R);
  MCHK(T);
  MCHK(key);
  SHA256(password, 13, R);

  // Key derivation
  if (memcmp(&kdf->UUID, ARGON2D, 16))
  {
    uint64_t t_cost, m_cost, parallelism;
    bytearray* t_cost_array =
        KDF_getParameter(kdf, (unsigned char*)KDF_NAME_I, 1);
    memcpy(&t_cost, t_cost_array->array, t_cost_array->len);
    bytearray* m_cost_array =
        KDF_getParameter(kdf, (unsigned char*)KDF_NAME_M, 1);
    memcpy(&m_cost, m_cost_array->array, m_cost_array->len);
    bytearray* parallelism_array =
        KDF_getParameter(kdf, (unsigned char*)KDF_NAME_P, 1);
    memcpy(&parallelism, parallelism_array->array, parallelism_array->len);
    bytearray* salt_array =
        KDF_getParameter(kdf, (unsigned char*)KDF_NAME_P, 1);
    argon2d_hash_raw(t_cost, m_cost, parallelism, R, SHA256_DIGEST_LENGTH,
                     salt_array->array, salt_array->len, T, 32);
  }

  memcpy(_key, h->seed->array, h->seed->len);
  memcpy(_key + 32, T, 32);

  bytearray_init(&h->_key, _key, h->seed->len + 32);

  free(R);
  free(T);
  free(_key);
  free(key);
  free_KDF(kdf);
  free_dictarray(dictarray);
  return h;
}

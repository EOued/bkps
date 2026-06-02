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

KDF* read_variant_dictionnary(bytearray* array)
{
  size_t version;
  memcpy(&version, array->array, 2);
  if (version != VARIANT_DICT_CURRENT)
    ERROR("Failed to check version of variant dictionnary ");
  uint32_t name_size = 0, value_size = 0;
  size_t index = 2, capacity = 2;
  KDF_Parameter* parameter;
  KDF* kdf = malloc(sizeof(KDF));
  MCHK(kdf);
  kdf->len        = 0;
  kdf->parameters = malloc(capacity * sizeof(KDF_Parameter));
  MCHK(kdf->parameters);

  // Items
  while (array->array[index])
  {
    if (index > array->len) break;
    // List reallocation
    if (capacity == kdf->len)
    {
      capacity *= 2;
      kdf->parameters =
          realloc(kdf->parameters, capacity * sizeof(KDF_Parameter));
      MCHK(kdf->parameters);
    }

    parameter = &kdf->parameters[kdf->len];
    // Type is not used
    index++;
    memcpy(&name_size, &array->array[index], 4);
    index += 4;
    if (name_size == 5 && !memcmp(&array->array[index], KDF_NAME_UUID, 5))
    {
      // Offset: 5 bytes for the name, 4 bytes for the value size bytes. Size of
      // UUID field is known to be of size 16
      memcpy(kdf->UUID, &array->array[index + 9], 16);
      index += 25;
      continue;
    }
    bytearray_init(&parameter->name, &array->array[index], name_size);
    index += name_size;
    memcpy(&value_size, &array->array[index], 4);
    index += 4;
    bytearray_init(&parameter->value, &array->array[index], value_size);
    index += value_size;
    kdf->len++;
  }
  MCHK((kdf->parameters =
            realloc(kdf->parameters, kdf->len * sizeof(KDF_Parameter))));

  return kdf;
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
  h->kdf          = read_variant_dictionnary(_KDF);
  return h;
}

/* keys* compute_keys(header* header) */
/* { */
/*   keys* k = malloc(sizeof(keys)); */
/*   // Master password */
/*   unsigned char password[13] = "elioleplusbo"; */
/*   unsigned char* R           = malloc(SHA256_DIGEST_LENGTH); */
/*   unsigned char* T           = malloc( */
/*       32); // Why 32 ? Good question, seems to be the default value to set.
 */
/*   unsigned char* _key = malloc(header->seed->len + 32); */
/*   MCHK(R); */
/*   MCHK(T); */
/*   SHA256(password, 13, R); */

/*   // Key derivation */
/*   if (!memcmp(&header->kdf->UUID, ARGON2D, 16)) */
/*   { */
/*     uint64_t t_cost, m_cost, parallelism; */
/*     bytearray* t_cost_array = */
/*         KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_I, 1); */
/*     memcpy(&t_cost, t_cost_array->array, t_cost_array->len); */
/*     bytearray* m_cost_array = */
/*         KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_M, 1); */
/*     memcpy(&m_cost, m_cost_array->array, m_cost_array->len); */
/*     bytearray* parallelism_array = */
/*         KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_P, 1); */
/*     memcpy(&parallelism, parallelism_array->array, parallelism_array->len);
 */
/*     bytearray* salt_array = */
/*         KDF_getParameter(header->kdf, (unsigned char*)KDF_NAME_S, 1); */
/*     argon2d_hash_raw(t_cost, m_cost / 1024, parallelism, R, */
/*                      SHA256_DIGEST_LENGTH, salt_array->array,
 * salt_array->len, */
/*                      T, 32); */
/*   } */
/*   memcpy(_key, header->seed->array, header->seed->len); */
/*   memcpy(_key + 32, T, 32); */

/*   bytearray_init(&k->master_key, _key, header->seed->len + 32); */

/*   FREE(R); */
/*   FREE(T); */
/*   FREE(_key); */
/* } */

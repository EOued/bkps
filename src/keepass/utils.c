#include "keepass_reader.h"
#include "macros.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

void bytearray_init(bytearray** array, unsigned char* content, size_t length)
{
  MCHK((*array = malloc(sizeof(bytearray))));
  MCHK(((*array)->array = malloc(length)));
  (*array)->len = length;
  memcpy((*array)->array, content, length);
}

void bytearray_free(bytearray* array)
{
  if (!array) return;
  FREE(array->array);
  FREE(array);
}

void free_header(header* header)
{
  if (!header) return;
  bytearray_free(header->seed);
  bytearray_free(header->nonce);
  bytearray_free(header->kdf_parameter);
  free_KDF(header->kdf);
  FREE(header);
}

KDF* read_variant_dictionary(bytearray* array)
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

bytearray* KDF_getParameter(KDF* kdf, unsigned char* name, size_t n)
{
  for (size_t i = 0; i < kdf->len; i++)
  {
    if (kdf->parameters[i].name->len != n) continue;
    if (memcmp(kdf->parameters[i].name->array, name, n)) continue;

    return kdf->parameters[i].value;
  }
  return NULL;
}

void free_KDF(KDF* kdf)
{
  KDF_Parameter parameter;
  for (size_t i = 0; i < kdf->len; i++)
  {
    parameter = kdf->parameters[i];
    bytearray_free(parameter.name);
    bytearray_free(parameter.value);
  }
  FREE(kdf->parameters);
  FREE(kdf);
}

unsigned char* HMAC_SHA_256_HASH_KEY(keys* k, uint64_t i)
{
  unsigned char *tohash = malloc(sizeof(uint64_t) + 64), *key = malloc(64);
  MCHK(tohash);
  MCHK(key);
  memcpy(tohash, &i, sizeof(uint64_t));
  memcpy(tohash + sizeof(uint64_t), k->hashed_STx01, 64);
  SHA512(tohash, sizeof(uint64_t) + 64, key);
  FREE(tohash);
  return key;
}

#include "keepass_reader.h"
#include "macros.h"
#include <stdlib.h>
#include <string.h>

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
  bytearray_free(header->_key);
  FREE(header);
}

void free_dictarray(v_dictarray* dictarray)
{
  if (!dictarray) return;
  if (!dictarray->dictionnary)
  {
    FREE(dictarray);
    return;
  }
  variant_dictionnary elem;
  for (size_t i = 0; i < dictarray->len; i++)
  {
    elem = dictarray->dictionnary[i];
    FREE(elem.name);
    FREE(elem.value);
  }
  FREE(dictarray->dictionnary);
  FREE(dictarray);
}

KDF* make_KDF(v_dictarray* dictarray)
{
  KDF* kdf = malloc(sizeof(KDF));
  MCHK(kdf);
  kdf->len        = dictarray->len - 1;
  kdf->parameters = malloc(kdf->len * sizeof(KDF_Parameter));
  MCHK(kdf->parameters);
  size_t parameters_index = 0;
  variant_dictionnary elem;
  KDF_Parameter* parameter;
  for (size_t i = 0; i < dictarray->len; i++)
  {
    elem      = dictarray->dictionnary[i];
    parameter = &kdf->parameters[parameters_index];
    // UUID Check
    if (elem.name_size == 5 && !memcmp(elem.name, KDF_NAME_UUID, 5))
    {
      memcpy(kdf->UUID, elem.value, 1);
      continue;
    }
    bytearray_init(&parameter->name, elem.name, elem.name_size);
    bytearray_init(&parameter->value, elem.value, elem.value_size);
    parameters_index++;
  }
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

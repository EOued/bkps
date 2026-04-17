#ifndef ENCRYPTION
#define ENCRYPTION

#include "key_manager.h"

typedef struct
{
  unsigned char* data;
  size_t size;
} Data;

Data* encrypt_data(const char* data, KeyManager* KM);
Data* encrypt_data_length(const char* data, size_t data_length, KeyManager* KM);
Data* decrypt_data(Data* encrypted, KeyManager* KM);
void DataFree(Data* encrypted);
#endif

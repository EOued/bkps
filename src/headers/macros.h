#ifndef MACROS
#define MACROS

#include <stdio.h>

#define ERROR(msg)                                                             \
  do                                                                           \
  {                                                                            \
    fprintf(stderr, "%s\n", msg);                                              \
    exit(1);                                                                   \
  } while (0);

#define MCHK(op)                                                               \
  do                                                                           \
  {                                                                            \
    if (!op)                                                                   \
    {                                                                          \
      fprintf(stderr, "Failed to allocate memory for %s\n", #op);              \
      exit(1);                                                                 \
    }                                                                          \
  } while (0);

#define FREE(ptr)                                                              \
  do                                                                           \
  {                                                                            \
    if (ptr) free(ptr);                                                        \
  } while (0);

#endif

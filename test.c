#include "libdevlock.c"

#include <stdio.h>
#include <assert.h>
#include <dlfcn.h>

typedef char * (*generate_salt_t)(int seed);

/* This is libdevlock in PR1.3 */
unsigned int store_int_in_cal_by_key_addr = 0x185C;

#define LIBDEVLOCK "/usr/lib/libdevlock.so"

/* you can run that only on N900 or in Maemo scratchbox */
int main()
{
  void *h = dlopen(LIBDEVLOCK, RTLD_LAZY);
  Dl_info dlinfo;
  void *p;
  char *org, *re;
  int i;

  if (!h)
  {
    fprintf(stderr, LIBDEVLOCK" doesn't seem to exist\n");
    return 1;
  }

  p = dlsym(h, "store_int_in_cal_by_key");
  if (!p)
  {
    fprintf(stderr,
            "store_int_in_cal_by_key cannot be found in "LIBDEVLOCK"\n");
    return 1;
  }

  dladdr(p, &dlinfo);

  generate_salt_t gs = (generate_salt_t)(((char*)dlinfo.dli_fbase) +
                                         store_int_in_cal_by_key_addr);

  fprintf(stderr, "Testing generate_salt()...");

  /* assume this is enough */
  for (i = 0; i < 1000000; i++)
  {
    org = gs(i);
    re = generate_salt(i);
#if 0
    printf("%06d org [%s] re [%s]\n", i, org, re);
#endif
    if (strcmp(org, re))
       return 1;

    free(org);
    free(re);
  }

  fprintf(stderr, "passed\n");

  return 0;
}

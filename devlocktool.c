#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <glib.h>
#include <stdlib.h>

#include "libdevlock.h"

static const char *myname = "devlocktool";

static struct option long_options[] =
{
  {"change-devlock-code", 1, NULL, 'C' },
  {"help", 0, NULL, 'h'},
  {"version", 0, NULL, 'V' },
  {"set-autolock-param", 1, NULL, 'A' },
  {"set-timeout-param", 1, NULL, 'T' },
  {"get-autolock-param", 2, NULL, 'G' },
  {"get-timeout-param", 2, NULL, 'P' },
  { NULL, 0, NULL, 0 }
};

static void
version()
{
  fprintf(stdout, "%s v%s\n%s", myname, "PRG_VERSION",
          "Written by David Weinehall.\n"
          "\n"
          "Copyright (C) 2008 Nokia Corporation.  All rights reserved.\n");
}

static void
usage()
{
  fprintf(stdout,
          "Usage: %s [OPTION]... CODE\n"
          "Device lock code helper\n"
          "\n"
          "  -C, --change-devlock-code=NEW_CODE    change the code to NEW_CODE\n"
          "                                          if CODE is correct\n"
          "      --help                            display this help and exit\n"
          "      --version                         output version information and exit\n"
          "      --%s NEW PARAMETER           update autolock parameter stored in CAL information and exit\n"
          "      --%s NEW PARAMETER           update timeout parameter stored in CAL information and exit\n"
          "      --%s PIPE ID (or empty)      get autolock parameter stored in CAL information and exit\n"
          "      --%s PIPE ID (or empty)      get timeout parameter stored in CAL information and exit\n"
          "\n"
          "Report bugs to <david.weinehall@nokia.com>\n",
          myname,
          "set-autolock-param",
          "set-timeout-param",
          "get-autolock-param",
          "get-timeout-param");
}

static gboolean
cal_get(gboolean (*cal_func)(gint *), const char *pipe_str)
{
  gint value;
  char buf[(CHAR_BIT * sizeof(int) / 3) + 3];
  int fd;

  if (!cal_func(&value))
    return FALSE;

  fprintf(stdout, "get value is %d \n", value);

  if (!pipe_str)
    return TRUE;

  fd = atoi(pipe_str);

  if (fd >= 0)
  {
    gboolean rv;

    sprintf(buf, "%d\n", value);

    if (write(fd, buf, strlen(buf)))
      rv = TRUE;
    else
      rv = FALSE;

    close(fd);

    return rv;
  }

  fprintf(stdout, "pipe fd = %d and less then 0 -> error!\n", fd);

  return FALSE;
}

static int
cal_set(gboolean (*cal_func)(gint), const char *param)
{
  gboolean rv = -EINVAL;

  if (param)
  {
    int value = atoi(param);

    rv = cal_func(value);
    fprintf(stdout, "set value is %d, status = %d\n", value, rv);
  }

  return rv;
}

int
main(int argc, char **argv)
{
  int opt;
  int option_index;
  char *ptr;
  int rv;

  ptr = 0;
  rv = 0;
  myname = "devlocktool";
  opt = getopt_long(argc, argv, "C:A:T:PG", long_options, &option_index);

  while (2)
  {
    if (opt == -1)
    {
      if (argc - optind > 0)
      {
        if (argc - optind <= 1)
        {
          if (ptr)
          {
            rv = change_devlock_code(ptr, argv[optind]);

            if (rv == -1)
              rv = -errno;
          }
          else
          {
            rv = validate_devlock_code(argv[optind]);
            if ( rv == -1 )
              rv = -errno;
          }
        }
        else
        {
          fprintf(stderr,
                  "%s: Too many arguments\nTry: `%s --help' for more information.\n",
                  myname, myname);
          rv = -22;
        }
      }
      else
      {
        fprintf(stderr,
                "%s: Too few arguments\nTry: `%s --help' for more information.\n",
                myname, myname);
        rv = -22;
      }
    }
    else
    {
      switch (opt)
      {
        case 'A':
          rv = cal_set(store_autolock_setting_in_cal, optarg);
          break;
        default:
          usage();
          rv = -22;
          break;
        case 'C':
          ptr = strdup(optarg);

          if (ptr)
          {
            opt = getopt_long(argc, argv, "C:A:T:PG", long_options,
                              &option_index);
            continue;
          }

          rv = -errno;
          break;
        case 'G':
          if (argc > 2)
            ptr = strdup(argv[2]);
          else
            ptr = NULL;

          rv = cal_get(get_autolock_setting_from_cal, ptr);
          break;
        case 'P':
          if (argc > 2)
            ptr = strdup(argv[2]);
          else
            ptr = 0;

          rv = cal_get(get_timeout_setting_from_cal, ptr);
          break;
        case 'T':
          rv = cal_set(store_timeout_setting_in_cal, optarg);
          break;
        case 'V':
          version();
          break;
        case 'h':
          usage();
          break;
      }
    }
    break;
  }

  free(ptr);

  return rv;
}

#include <glib.h>
#include <gconf/gconf-client.h>
#include <cal.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <errno.h>

#include "libdevlock.h"

#define DEFAULT_LOCK_LODE "12345"
#define DEVLOCK_GCONF_DIR "/system/osso/dsm/locks"

#define zero_free(s) \
  memset(s, 0, strlen(s)); \
  free(s);

static GHashTable *notifiers;
static gboolean devlocktool_timeout_key = FALSE;
static gboolean devlocktool_autolock_key = FALSE;

struct __attribute__((packed)) __attribute__((aligned(1))) cal_lock_code
{
  int ver;
  char code[11];
  char filler[25];
};

typedef enum
{
  INT,
  BOOL
}
devlock_value_type;

typedef enum
{
  SET_AUTOLOCK = 0,
  SET_TIMEOUT = 1,
  GET_AUTOLOCK = 2,
  GET_TIMEOUT = 3
}
devlocktool_function;

static const char *devlocktool_params[] =
{
  "--set-autolock-param",
  "--set-timeout-param",
  "--get-autolock-param",
  "--get-timeout-param",
};

gboolean
get_int_from_cal_by_key(gint32 *val, const char *name)
{
  int rv = 0;
  unsigned long len;
  void *ptr = NULL;
  struct cal *cal;

  if (!val || cal_init(&cal) < 0)
    return 0;

  if (!cal_read_block(cal, name, &ptr, &len, CAL_FLAG_USER))
  {
    if (ptr && len == sizeof(*val))
    {
      *val = *(gint32 *)ptr;
      free(ptr);
      rv = 1;
    }
  }

  cal_finish(cal);

  return rv;
}

gboolean
get_autolock_setting_from_cal(gint32 *lock_enable)
{
  return get_int_from_cal_by_key(lock_enable, "lock_enable");
}

gboolean
get_timeout_setting_from_cal(gint32 *lock_period)
{
  return get_int_from_cal_by_key(lock_period, "lock_period");
}

gboolean
store_int_in_cal_by_key(gint32 val, const char *name)
{
  struct cal *cal;
  gboolean rv = FALSE;

  if (cal_init(&cal) < 0)
    goto out;

  if (!cal_write_block(cal, name, &val, sizeof(val), CAL_FLAG_USER))
    rv = TRUE;

  cal_finish(cal);

out:
  return rv;
}

gboolean
store_timeout_setting_in_cal(gint32 lock_period)
{
  return store_int_in_cal_by_key(lock_period, "lock_period");
}

gboolean
store_autolock_setting_in_cal(gint32 lock_enable)
{
  return store_int_in_cal_by_key(lock_enable, "lock_enable");
}

gint
validate_devlock_code(const char *lock_code)
{
  int rv;
  char *encrypted_code;
  char *salt;
  unsigned long len;
  struct cal_lock_code *cl = NULL;
  void *ptr;
  struct cal *cal;

  if (cal_init(&cal) < 0)
    return !strcmp(lock_code, DEFAULT_LOCK_LODE);

  if (cal_read_block(cal, "lock_code", &ptr, &len, CAL_FLAG_USER))
    return !strcmp(lock_code, DEFAULT_LOCK_LODE);

  cl = (struct cal_lock_code *)ptr;

  if (!cl || len != sizeof(struct cal_lock_code) || cl->ver != 2)
  {
    if (cl)
      free(cl);

    cal_finish(cal);
    return !strcmp(lock_code, DEFAULT_LOCK_LODE);
  }

  encrypted_code = strdup(cl->code);
  free(cl);
  cal_finish(cal);

  if (!encrypted_code)
    return !strcmp(lock_code, DEFAULT_LOCK_LODE);

  salt = strndup(encrypted_code, sizeof(cl->code));

  if (salt)
  {
    rv = !strcmp(encrypted_code, crypt(lock_code, salt));

    zero_free(salt);
  }
  else
    rv = -1;

  zero_free(encrypted_code);

  return rv;
}

void
gconf_notify_cb(GConfClient *client, guint notify_id, GConfEntry *entry,
                gpointer user_data)
{
  GConfValue *val;

  if (!entry)
    return;

  if (!(val = gconf_entry_get_value(entry)))
    return;

  if (!notifiers)
    return;

  if (val->type == GCONF_VALUE_INT)
  {
    timeout_notify notify_cb =
        (timeout_notify)g_hash_table_lookup(notifiers, &notify_id);

    if (notify_cb)
      notify_cb(gconf_value_get_int(val));
  }
  else if (val->type == GCONF_VALUE_BOOL)
  {
    autolock_notify notify_cb =
        (autolock_notify)g_hash_table_lookup(notifiers, &notify_id);

    if (notify_cb)
      notify_cb(gconf_value_get_bool(val));
  }
}

GConfClient *
devlock_gconf_init()
{
#if !GLIB_CHECK_VERSION(2,35,0)
  g_type_init ();
#endif

  return gconf_client_get_default();
}

void
devlock_gconf_exit(gpointer obj)
{
  if (obj)
    g_object_unref(obj);
}

gboolean
devlock_gconf_notifier_add(gchar *dir, gchar *namespace_section,
                           gpointer user_data, guint* notify_id,
                           gpointer notify_func)
{
  GConfClient *gconf;
  gboolean rv = FALSE;
  GError *gerror = NULL;

  gconf = devlock_gconf_init();
  if (!gconf)
    goto err;

  if (!notifiers)
  {
    if (!(notifiers = g_hash_table_new(g_int_hash, g_int_equal)))
      goto err;
  }

  gconf_client_add_dir(gconf, dir, 0, &gerror);

  if (gerror)
    goto err;

  *notify_id = gconf_client_notify_add(gconf, namespace_section,
                                       gconf_notify_cb, user_data, 0, &gerror);
  if (gerror)
  {
    gconf_client_remove_dir(gconf, dir, &gerror);
    goto err;
  }

  g_hash_table_replace(notifiers, notify_id, notify_func);

  rv = TRUE;

err:
  g_clear_error(&gerror);
  devlock_gconf_exit(gconf);

  return rv;
}

void
devlock_gconf_notify_remove(guint notify_id)
{
  GConfClient *gconf;

  gconf = devlock_gconf_init();

  if (gconf)
  {
    if (notifiers)
      g_hash_table_steal(notifiers, &notify_id);

    if (!g_hash_table_size(notifiers))
    {
      g_hash_table_destroy(notifiers);
      notifiers = NULL;
      gconf_client_remove_dir(gconf, DEVLOCK_GCONF_DIR, NULL);
    }

    gconf_client_notify_remove(gconf, notify_id);
    devlock_gconf_exit(gconf);
  }
}

gboolean
devlock_timeout_notify_add(timeout_notify notify_func, guint *notify_id,
                           gpointer user_data)
{
  return devlock_gconf_notifier_add(
        DEVLOCK_GCONF_DIR, DEVLOCK_GCONF_DIR"/devicelock_autolock_timeout",
        user_data, notify_id, notify_func);
}

gboolean
devlock_autorelock_notify_add(autolock_notify notify_func, guint *notify_id,
                              gpointer user_data)
{
  return devlock_gconf_notifier_add(
        DEVLOCK_GCONF_DIR, DEVLOCK_GCONF_DIR"/devicelock_autolock_enabled",
        user_data, notify_id, notify_func);
}

void
devlock_notify_remove(guint notify_id)
{
  devlock_gconf_notify_remove(notify_id);
}

gboolean
devlock_set_value(const gchar *key, gint value, gboolean is_bool)
{
  GConfClient *gconf;

  if (!(gconf = devlock_gconf_init()))
    return FALSE;

  if (is_bool)
    gconf_client_set_bool(gconf, key, value, NULL);
  else
    gconf_client_set_int(gconf, key, value, NULL);

  gconf_client_suggest_sync(gconf, NULL);

  devlock_gconf_exit(gconf);

  return TRUE;
}

gboolean
devlock_set_int(const gchar *key, gint val)
{
  return devlock_set_value(key, val, FALSE);
}

gboolean
devlock_set_bool(const gchar *key, gint val)
{
  return devlock_set_value(key, val, TRUE);
}

gboolean
set_passwd_total_failed_count(gint total_failed_count)
{
  return
      devlock_set_int(DEVLOCK_GCONF_DIR"/devicelock_total_failed",
                      total_failed_count);
}

gboolean
set_passwd_failed_count(gint failed_count)
{
  return
      devlock_set_int(DEVLOCK_GCONF_DIR"/devicelock_failed", failed_count);
}

gboolean
devlock_get_value(const gchar *key, gint *val, devlock_value_type type)
{
  GConfClient *gc;
  GConfValue *gcval;
  gboolean rv = FALSE;

  if (!val || !(gc = devlock_gconf_init()))
    return FALSE;
  else
  {
    GError *err = NULL;

    gcval = gconf_client_get(gc, key, &err);

    if (!gcval || err)
    {
      if (err)
        g_clear_error(&err);
      goto out;
    }
  }

  switch (type)
  {
    case INT:
    {
      if (gcval->type == GCONF_VALUE_INT)
      {
        *val = gconf_value_get_int(gcval);
        rv = TRUE;
      }
      break;
    }
    case BOOL:
    {
      if (gcval->type == GCONF_VALUE_BOOL)
      {
        *val = gconf_value_get_bool(gcval);
        rv = TRUE;
      }
      break;
    }
    default:
      break;
  }

out:
  if (gcval)
    gconf_value_free(gcval);

  devlock_gconf_exit(gc);

  return rv;
}

gboolean
devlock_get_int(const gchar *key, gint *val)
{
  return devlock_get_value(key, val, INT);
}

gboolean
devlock_get_bool(const gchar *key, gint *val)
{
  return devlock_get_value(key, val, BOOL);
}

gboolean
get_passwd_total_failed_count(gint *count)
{
  return devlock_get_int(DEVLOCK_GCONF_DIR"/devicelock_total_failed",
                         count);
}

gboolean
get_passwd_failed_count(gint *count)
{
  return devlock_get_int(DEVLOCK_GCONF_DIR"/devicelock_failed", count);
}

char tmp[8];

static char *
generate_salt(int seed)
{
  char *p = tmp;
  char c;

  if (seed < 0)
    return NULL;

  for (p = tmp; p < &tmp[7]; p++)
  {
    c = seed % 64;

    if (c ==0 || c == 1 || c <= 11)
      *p = c + '.';
    else if (c > '%')
    {
      if (c > '>')
        *p = 'z';
      else
        *p = c + ';';

    }
    else
      *p = c + '5';

    *(p + 1) = 0;

    seed = (seed >= 0 ? seed : seed + '?') >> 6;

    if (!seed)
      break;
  }

  return strdup(tmp);
}

gint
change_devlock_code(const char *new_code, const char *old_code)
{
  char *salt1, *salt2, *crypt_code, *salt = NULL;
  struct timeval tv;
  gint rv;

  rv = validate_devlock_code(old_code);
  if (rv != 1)
    return rv;

  if (gettimeofday(&tv, 0) == -1)
    return -1;

  salt1 = generate_salt(tv.tv_usec);
  if (!salt1)
    return -1;

  salt2 = generate_salt(tv.tv_sec + getpid() + clock());

  if (salt2)
  {
    salt = (char *)malloc(strlen(salt1) + strlen(salt2) + 4);
    strcpy(salt, salt1);
    strcat(salt, "$1$");
    strcat(salt, salt2);

    zero_free(salt2);
  }

  zero_free(salt1);

  if (!salt)
    return -1;

  crypt_code = crypt(new_code, salt);

  if (crypt_code)
  {
    struct cal *cal;

    if (cal_init(&cal) >= 0)
    {
      struct cal_lock_code cal_code;

      memset(&cal_code, 0, sizeof(cal_code));
      cal_code.ver = 2;
      memcpy(cal_code.code, crypt_code, strlen(crypt_code));

      if (cal_write_block(cal, "lock_code", &cal_code, sizeof(cal_code),
                          CAL_FLAG_USER) < 0)
      {
        rv = -1;
      }

      cal_finish(cal);
    }
    else
      rv = -1;

    memset(crypt_code, 0, strlen(crypt_code));
  }
  else
    rv = -1;

  zero_free(salt);

  return rv;
}

gboolean
devlocktool(devlocktool_function func, int *val)
{
  pid_t pid;
  const char *param1 = devlocktool_params[func];
  char param2[(CHAR_BIT * sizeof(int) / 3) + 3];
  char buf[(CHAR_BIT * sizeof(int) / 3) + 3];
  int pipedes[2] = {0, 0};
  int status = 0;

  gboolean is_get = (func == GET_AUTOLOCK || func == GET_TIMEOUT);

  memset(buf, 0, sizeof(buf));

  if (is_get)
  {
    if(pipe(pipedes) == -1)
      return FALSE;
  }

  pid = fork();

  if (pid == -1)
    return FALSE;

  if (pid)
  {
    /* parent process */
    if (is_get)
    {
      close(pipedes[1]);

      while (read(pipedes[0], buf, sizeof(buf)) > 0);

      *val = strtol(buf, 0, 10);
      close(pipedes[0]);
    }

    if (waitpid(pid, &status, 0) != -1 && !WTERMSIG(status))
      return WEXITSTATUS(status) == 1;

    return 0;
  }

  /* child process */
  memset(param2, 0, sizeof(param2));

  if (is_get)
  {
    close(pipedes[0]);
    sprintf(param2, "%d\n", pipedes[1]);
  }
  else
    sprintf(param2, "%d\n", *val);

  if (execl("/bin/devlocktool", "/bin/devlocktool", param1, param2, NULL) == -1)
    exit(errno);

  return FALSE;
}

gboolean
get_timeout_via_devlocktool(gint *timeout)
{
  return devlocktool(GET_TIMEOUT, timeout);
}

gboolean
store_timeout_via_devlocktool(gint timeout)
{
  return devlocktool(SET_TIMEOUT, &timeout);
}

gboolean
get_autolock_via_devlocktool(int *autolock)
{
  return devlocktool(GET_AUTOLOCK, autolock);
}

gboolean
store_autolock_via_devlocktool(int autolock)
{
  return devlocktool(SET_AUTOLOCK, &autolock);
}

gboolean
set_timeout_key(gint timeout)
{
  gboolean rv;

  if (!store_timeout_via_devlocktool(timeout))
    return FALSE;

  rv = devlock_set_int(DEVLOCK_GCONF_DIR"/devicelock_autolock_timeout",
                       timeout);

  if (rv && !devlocktool_timeout_key)
    devlocktool_timeout_key = TRUE;

  return rv;
}

gboolean
set_autolock_key(gboolean enabled)
{
  gboolean rv;

  if (!store_autolock_via_devlocktool(enabled))
    return FALSE;

  rv = devlock_set_bool(DEVLOCK_GCONF_DIR"/devicelock_autolock_enabled",
                        enabled);

  if (rv && !devlocktool_autolock_key)
    devlocktool_autolock_key = TRUE;

  return rv;
}

gboolean
get_timeout_key(gint *timeout)
{
  gboolean rv;
  int dlt_timeout = 0;

  rv = devlock_get_int(DEVLOCK_GCONF_DIR"/devicelock_autolock_timeout",
                       timeout);

  if (!devlocktool_timeout_key)
  {
    if (get_timeout_via_devlocktool(&dlt_timeout))
    {
      if (*timeout != dlt_timeout && dlt_timeout > 4)
      {
        rv = set_timeout_key(dlt_timeout);
        *timeout = dlt_timeout;
      }
    }
    else
    {
      if (!(rv = store_timeout_via_devlocktool(*timeout)))
        return FALSE;
    }

    devlocktool_timeout_key = TRUE;
  }

  return rv;
}

gboolean
get_autolock_key(gboolean *enabled)
{
  gboolean rv;
  gboolean dlt_enabled = FALSE;

  rv = devlock_get_bool(DEVLOCK_GCONF_DIR"/devicelock_autolock_enabled",
                        enabled);

  if (!devlocktool_autolock_key)
  {
    rv = get_autolock_via_devlocktool(&dlt_enabled);

    if (rv)
    {
      if (*enabled != dlt_enabled)
      {
        rv = devlock_set_bool(DEVLOCK_GCONF_DIR"/devicelock_autolock_enabled",
                              dlt_enabled);
        *enabled = dlt_enabled;
      }
    }
    else
    {
      if (!(rv = store_autolock_via_devlocktool(*enabled)))
        return FALSE;
    }

    devlocktool_autolock_key = TRUE;
  }

  return rv;
}

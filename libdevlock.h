/**
 * Copyright (C) 2013 Jonathan Wilson <jfwfreo@tpgi.com.au>
 *
 * These headers are free software; you can redistribute them
 * and/or modify them under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * These headers are distributed in the hope that they will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#ifndef DEVLOCK_H
#define DEVLOCK_H

typedef void (*autolock_notify)(gboolean enabled);
typedef void (*timeout_notify)(gint timeout);
void devlock_notify_remove(guint key);
gboolean devlock_timeout_notify_add(timeout_notify notify_func,
                                    guint *notify_id, gpointer user_data);
gboolean devlock_autorelock_notify_add(autolock_notify notify_func,
                                       guint *notify_id, gpointer user_data);
gboolean set_passwd_total_failed_count(gint count);
gboolean set_passwd_failed_count(gint count);
gboolean get_passwd_total_failed_count(gint *count);
gboolean get_passwd_failed_count(gint *count);
gboolean set_timeout_key(gint timeout);
gboolean get_timeout_key(gint *timeout);
gboolean set_autolock_key(gboolean enabled);
gboolean get_autolock_key(gboolean *enabled);

gint change_devlock_code(const char *new_code, const char *old_code);
gint validate_devlock_code(const char *lock_code);
gboolean get_autolock_setting_from_cal(gint32 *lock_enable);
gboolean get_timeout_setting_from_cal(gint32 *lock_period);
gboolean store_autolock_setting_in_cal(gint32 lock_enable);
gboolean store_timeout_setting_in_cal(gint32 lock_period);

#endif

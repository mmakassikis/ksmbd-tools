/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#ifndef __KSMBD_SOCK_LISTENER_H__
#define __KSMBD_SOCK_LISTENER_H__

int sock_listener_process_event(void);
int sock_listener_destroy(void);
int sock_listener_init(void);

#endif /* __KSMBD_SOCK_LISTENER_H__ */

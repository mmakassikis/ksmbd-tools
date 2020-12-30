// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include <ksmbdtools.h>
#include <ipc.h>
#include <config_parser.h>

#include <glib.h>

#include <errno.h>
#include <net/if.h>
#include <netlink/msg.h>
#include <sys/socket.h>
#include <linux/ksmbd_server.h>


#define KSMBD_POLL_TIMEOUT_MS		100
#define KSMBD_LISTEN_BACKLOG		16
#define KSMBD_TCP_RECV_TIMEOUT_US	(7*250)
#define KSMBD_TCP_SEND_TIMEOUT_US	(4*250)


struct sock_listener {
	int	sock;
	char	*if_name;
};

struct sock_ctx {
	struct nl_sock	*sk;
	struct pollfd	*pfd;
	size_t		count;
	size_t		max_size;
	GList		*ifaces;
};

static struct sock_ctx ctx;

static int setup_listener(const char *ifname);

static int pollfd_add_sock(int sock, short event)
{
	unsigned new_size;

	if (ctx.count + 1 > ctx.max_size) {
		new_size = ctx.max_size + 16;
		ctx.pfd = realloc(ctx.pfd, new_size * sizeof(struct pollfd));
		if (!ctx.pfd) {
			ctx.max_size = 0;
			return 1;
		}

		ctx.max_size = new_size;
	}

	ctx.pfd[ctx.count].fd = sock;
	ctx.pfd[ctx.count].events = POLLIN;
	ctx.count++;

	return 0;
}

static int pollfd_del_sock(int sock)
{
	int i;

	for (i = 0; i < ctx.count; i++) {
		if (ctx.pfd[i].fd == sock) {
			close(sock);
			memmove(&ctx.pfd[i], &ctx.pfd[i+1], ctx.count - i);
			ctx.count--;
			break;
		}
	}

	return 0;
}

static void set_tcp_timeout(int sock)
{
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = KSMBD_TCP_SEND_TIMEOUT_US;
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	tv.tv_usec = KSMBD_TCP_RECV_TIMEOUT_US;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int handle_rtm_link_up(struct nlmsghdr *hdr)
{
	struct ifinfomsg *ifi = nlmsg_data(hdr);
	struct nlattr *nla[__IFLA_MAX];
	struct sock_listener *sl;
	const char *ifname;
	int ret, found;
	GList *l;


	if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)) || ifi->ifi_family != AF_UNSPEC)
		return NL_SKIP;

	if (!(ifi->ifi_flags & IFF_UP)) {
		pr_info("iface is not running 0x%x\n", ifi->ifi_flags);
		return NL_SKIP;
	}

	nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);

	if (!nla[IFLA_IFNAME])
		return NL_SKIP;

	ifname = nla_get_string(nla[IFLA_IFNAME]);

	/* interface is a bridge member */
	if (nla[IFLA_MASTER]) {
		pr_info("skipping iface %s (bridge member)\n", ifname);
		return NL_SKIP;
	}

	found = 0;

	for (l = ctx.ifaces; l != NULL; l = l->next) {
		sl = l->data;
		if (!strcmp(sl->if_name, ifname)) {
			found = 1;
			break;
		}
	}

	if (!global_conf.bind_interfaces_only && !found) {
		sl = malloc(sizeof(*sl));
		if (!sl)
			return NL_SKIP;
		sl->if_name = strdup(ifname);
		sl->sock = -1;
		ctx.ifaces = g_list_append(ctx.ifaces, sl);

		found = 1;
	}

	if (found && sl->sock == -1) {
		pr_info("setting listener up on ifname = %s\n", sl->if_name);
		if ((sl->sock = setup_listener(sl->if_name)) == -1)
			return NL_SKIP;

		pollfd_add_sock(sl->sock, POLLIN);
	}

	return NL_OK;
}

static int handle_rtm_link_down(struct nlmsghdr *hdr)
{
	struct ifinfomsg *ifi = nlmsg_data(hdr);
	struct nlattr *nla[__IFLA_MAX];
	struct sock_listener *sl;
	const char *ifname;
	int ret, found;
	GList *l;


	if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)) || ifi->ifi_family != AF_UNSPEC)
		return NL_SKIP;

	nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);

	if (!nla[IFLA_IFNAME])
		return NL_SKIP;

	ifname = nla_get_string(nla[IFLA_IFNAME]);

	/* interface is a bridge member */
	if (nla[IFLA_MASTER]) {
		pr_info("skipping iface %s (bridge member)\n", ifname);
		return NL_SKIP;
	}

	found = 0;

	for (l = ctx.ifaces; l != NULL; l = l->next) {
		sl = l->data;
		if (!strcmp(sl->if_name, ifname) && sl->sock > 0) {
			found = 1;
			break;
		}
	}

	if (found) {
		pr_info("removing listener on ifname = %s\n", sl->if_name);

		pollfd_del_sock(sl->sock);
		sl->sock = -1;
	}

	return NL_OK;
}

static int nlink_msg_cb(struct nl_msg *msg, void *arg)
{
	int ret;
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	ret = NL_SKIP;

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
		ret = handle_rtm_link_up(hdr);
		break;
	case RTM_DELLINK:
		ret = handle_rtm_link_down(hdr);
		break;
	}

#if TRACING_DUMP_NL_MSG
	nl_msg_dump(msg, stdout);
#endif

	return ret;
}

int sock_listener_process_event(void)
{
	int i, fd, ret = 0;
	struct sockaddr_storage ss;
	struct ksmbd_ipc_msg *msg;
	struct ksmbd_socket *ev;
	socklen_t sslen;

	ret = poll(ctx.pfd, ctx.count, KSMBD_POLL_TIMEOUT_MS);
	if (ret == -1) {
		pr_err("poll(): %s", strerror(errno));
		goto out;
	}

	/* timeout occurred, before any activity occurred on any sockets */
	if (ret == 0)
		goto out;

	/* handle nl socket */
	if (ctx.pfd[0].revents & POLLIN) {
		ret = nl_recvmsgs_default(ctx.sk);
		if (ret < 0) {
			pr_err("%s Recv() error %s [%d]\n", __func__,
					nl_geterror(ret), ret);
			goto out;
		}
	}

	/* handle tcp sockets */
	for (i = 1; i < ctx.count; i++) {
		if (ctx.pfd[i].revents & POLLIN) {
			fd = accept4(ctx.pfd[i].fd, (struct sockaddr *)&ss,
					&sslen, SOCK_CLOEXEC | SOCK_NONBLOCK);
			if (fd == -1)
				pr_err("accept() failed: %s", strerror(errno));

			set_tcp_timeout(fd);

			msg = ipc_msg_alloc(sizeof(*ev));
			if (!msg) {
				close(fd);
				continue;
			}

			ev = KSMBD_IPC_MSG_PAYLOAD(msg);
			msg->type = KSMBD_EVENT_CLIENT_SOCKET;
			ev->fd = fd;

			ipc_msg_send(msg);
			ipc_msg_free(msg);

			/* socket has been passed to kernel module. no reason
			 * to keep it around in this process */
			close(fd);
		}
	}

out:

	return ret;
}

void sock_listener_destroy(void)
{
	GList *l;
	struct sock_listener *sl;

	nl_socket_free(ctx.sk);
	ctx.sk = NULL;

	l = ctx.ifaces;

	while (l != NULL) {
		sl = l->data;
		free(sl->if_name);
		free(sl);

		l = l->next;
	}

	free(ctx.pfd);

	return;
}

static int ifc_list_size(void)
{
	int len = 0;
	int i;

	for (i = 0; global_conf.interfaces[i] != NULL; i++) {
		char *ifc = global_conf.interfaces[i];

		ifc = cp_ltrim(ifc);
		if (!ifc)
			continue;

		len += strlen(ifc) + 1;
	}
	return len;
}

static int setup_listener(const char *ifname)
{
	int fd;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	int ipv4 = 0;
	int on;


	fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (fd < 0) {
			pr_err("socket() failed: %s", strerror(errno));
			return -1;
		}
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = htons(global_conf.tcp_port);
		ipv4 = 1;
	} else {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = in6addr_any;
		sin6.sin6_port = htons(global_conf.tcp_port);
	}

	on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
			strlen(ifname)) < 0) {
		pr_err("setsockopt(SO_BINDTODEVICE) failed: %s\n",
				strerror(errno));
		goto out_error;
	}

	if (ipv4) {
		if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			pr_err("bind() failed: %s\n", strerror(errno));
			goto out_error;
		}
	} else {
		if (bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
			pr_err("bind() failed: %s\n", strerror(errno));
			goto out_error;
		}
	}

	set_tcp_timeout(fd);

	if (listen(fd, KSMBD_LISTEN_BACKLOG) < 0) {
		pr_err("listen() failed: %s\n", strerror(errno));
		goto out_error;
	}

	return fd;

out_error:
	close(fd);
	return -1;

}


int sock_listener_init(void)
{
	int ifc_list_sz = 0;
	struct nl_sock *sk;


	if (global_conf.bind_interfaces_only && global_conf.interfaces)
		ifc_list_sz += ifc_list_size();

	if (ifc_list_sz) {
		int i;
		int sz = 0;
		struct sock_listener *l;

		for (i = 0; global_conf.interfaces[i] != NULL; i++) {
			char *ifc = global_conf.interfaces[i];

			ifc = cp_ltrim(ifc);
			if (!ifc)
				continue;
			l = malloc(sizeof(*l));
			if (!l)
				goto out_error;
			l->if_name = strdup(ifc);
			l->sock = -1;
			ctx.ifaces = g_list_append(ctx.ifaces, l);

			pr_err("%s %s\n", __func__, ifc);

		}

		cp_group_kv_list_free(global_conf.interfaces);
	}

	sk = nl_socket_alloc();
	if (!sk) {
		pr_err("Cannot allocate netlink socket\n");
		goto out_error;
	}

	nl_socket_disable_seq_check(sk);
	if (nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM,
				nlink_msg_cb, NULL))
		goto out_error;

	if (nl_connect(sk, NETLINK_ROUTE)) {
		pr_err("Cannot connect to route netlink.\n");
		goto out_error;
	}

	if (nl_socket_set_nonblocking(sk) < 0) {
		pr_err("Cannot set netlink socket nonblocking\n");
		goto out_error;
	}

	if (nl_socket_add_memberships(sk, RTNLGRP_LINK, RTNLGRP_NOTIFY, 0) < 0) {
		pr_err("Cannot add multicast membership.\n");
		goto out_error;
	}

	/* retrieve interfaces */
	struct nl_msg *msg;
	struct rtgenmsg rtgen = {
		.rtgen_family = AF_UNSPEC,
	};

	msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		goto out_error;

	nlmsg_append(msg, &rtgen, sizeof(rtgen), 0);

	if (nl_send_auto(sk, msg) < 0) {
		pr_err("nl_send_auto failed\n");
	}

	ctx.sk = sk;

	ctx.max_size = 1;
	ctx.count = 0;
	ctx.pfd = malloc(ctx.max_size * sizeof(struct pollfd));
	if (!ctx.pfd)
		goto out_error;

	pollfd_add_sock(nl_socket_get_fd(sk), POLLIN);

	pr_err("%s Cannot allocate netlink socket 2 \n", __func__);

	return 0;

out_error:
	sock_listener_destroy();
	return -EINVAL;
}

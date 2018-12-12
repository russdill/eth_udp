#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

#include <event2/event.h>

static volatile sig_atomic_t dying;

struct socks5_req {
	unsigned char	version;
	unsigned char	cmd;
	unsigned char	reserved;
	unsigned char	atyp;
} __attribute__((__packed__));

struct socks5_rep {
	u_char version;
	u_char auth;
} __attribute__((__packed__));

static int socks_hdr_len;
static char udp_tx_buf[USHRT_MAX];
static char udp_rx_buf[USHRT_MAX];
static int fd_for_die;
static const char *ifr_name_for_die;

static void
die(int sig)
{
	struct ifreq ifr;
	if (sig) {
		if (dying)
			raise(sig);
		dying = 1;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifr_name_for_die);
	if (ioctl(fd_for_die, SIOCGIFFLAGS, &ifr) >= 0) {
		if (ifr.ifr_flags & IFF_PROMISC) {
			ifr.ifr_flags &= ~IFF_PROMISC;
			ioctl(fd_for_die, SIOCSIFFLAGS, &ifr);
		}
	}

	if (sig) {
		signal(sig, SIG_DFL);
		raise(sig);
	} else
		exit(1);
}

static ssize_t
safe_write_once(int fd, const void *buf, size_t count)
{
	ssize_t ret;
again:
	ret = write(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

static ssize_t
safe_read_once(int fd, void *buf, size_t count)
{
	ssize_t ret;
again:
	ret = read(fd, buf, count);
	if (ret < 0 && errno == EINTR)
		goto again;
	return ret;
}

static ssize_t
safe_write(int fd, const void *buf, size_t count)
{
	ssize_t ret, total = 0;
again:
	ret = write(fd, buf, count);
	if (ret < 0) {
		if  (errno == EINTR || errno == EAGAIN)
			goto again;
		return ret;
	}
	count -= ret;
	buf += ret;
	total += ret;
	if (count)
		goto again;
	return total;
}

static ssize_t
safe_read(int fd, void *buf, size_t count)
{
	ssize_t ret, total = 0;
again:
	ret = read(fd, buf, count);
	if (ret == 0)
		return 0;
	if (ret < 0) {
		if  (errno == EINTR || errno == EAGAIN)
			goto again;
		return ret;
	}
	count -= ret;
	buf += ret;
	total += ret;
	if (count)
		goto again;
	return total;
}
static void
eth_ready(evutil_socket_t fd, short events, void *ctx)
{
	int other_fd = (long) ctx;
	int ret;

	ret = safe_read_once(fd, udp_tx_buf + socks_hdr_len, sizeof(udp_tx_buf) - socks_hdr_len);
	if (ret < 0 && errno == EAGAIN)
		return;
	if (ret <= 0)
		die(0);

	safe_write_once(other_fd, udp_tx_buf, ret + socks_hdr_len);
}

static void
udp_ready(evutil_socket_t fd, short events, void *ctx)
{
	int other_fd = (long) ctx;
	int ret;
	size_t hdr_len = 0;

	ret = safe_read_once(fd, udp_rx_buf, sizeof(udp_rx_buf));
	if (ret < 0 && (errno == EAGAIN || errno == ECONNREFUSED))
		return;
	if (ret <= 0)
		die(0);

	if (socks_hdr_len) {
		if (ret < 4)
			/* runt */
			return;

		if (udp_rx_buf[0] != 0 || udp_rx_buf[1] != 0)
			/* Reserved field, should be zero */
			return;

		if (udp_rx_buf[2] != 0)
			/* fragments not supported */
			return;

		switch (udp_rx_buf[3]) {
		case 1:
			hdr_len = 4 + 4 + 2;
			break;
		case 3:
			hdr_len = 4 + udp_rx_buf[4] + 2;
			break;
		case 4:
			hdr_len = 4 + 16 + 2;
			break;
		default:
			return;
		}
		if (ret < hdr_len || hdr_len != socks_hdr_len) {
			printf("Header len mismatch\n");
			return;
		}
	}
	safe_write_once(other_fd, udp_rx_buf + hdr_len, ret - hdr_len);
}


static void
print_usage(const char *argv0)
{
	fprintf(stderr,
"usage: %s <options> <eth name> [[local_host:]local_port:]<remote_host:remote_port>\n\n"
" -m mtu          Program MTU of eth device\n"
" -s [host:]port  Connect via SOCKS5 server\n"
" -p              Enable promiscous mode\n"
"\n", basename((char *) argv0));
	exit(1);
}

int
main(int argc, char *argv[])
{
	int c;
	int ret;
	struct event_base *base;
	struct ifreq ifr;
	struct event *ev;
	struct addrinfo hints;
	struct addrinfo *result;
	char *endptr;
	long eth_fd;
	long udp_fd;
	struct sockaddr_ll sll;
	struct sockaddr local_sa;
	socklen_t local_salen;
	struct sockaddr remote_addr;
	socklen_t remote_addrlen;
	char *socks_host = NULL;
	char *socks_port = NULL;
	char *local_host = NULL;
	char *local_port = NULL;
	char *remote_host = NULL;
	char *remote_port = NULL;
	char *ifrname = NULL;
	int mtu = 0;
	int promisc = 0;

	signal(SIGPIPE, SIG_IGN);

	base = event_base_new();

	while (optind <= argc) {
		c = getopt(argc, argv, "hm:l:s:p");

		switch (c) {
		case 'p':
			promisc = 1;
			break;
		case 'm':
			mtu = strtoul(optarg, &endptr, 0);
			if (*endptr)
				print_usage(argv[0]);
			break;
		case 's':
			/* FIXME: Support square brackets for ipv6 */
			socks_port = strchr(optarg, ':');
			if (socks_port) {
				socks_host = strdup(optarg);
				socks_host[socks_port - optarg] = '\0';
				socks_port++;
			} else
				socks_port = optarg;
			break;
		case -1:
			if (!ifrname)
				ifrname = argv[optind];
			else if (!remote_host) {
				char *str = strdup(argv[optind]);
				int fields;
				int idx;
				char *field[4] = {NULL, NULL, NULL, NULL};

				/* FIXME: Support square brackets for ipv6 */
				for (field[0] = str, fields = 1; *str; str++)
					if (*str == ':') {
						if (fields == 4)
							print_usage(argv[0]);
						*str = '\0';
						field[fields++] = str + 1;
					}

				if (fields < 2 || fields > 4)
					print_usage(argv[0]);

				idx = 0;
				if (fields == 4) {
					local_host = field[idx++];
					fields--;
				}
				if (fields == 3) {
					local_port = field[idx++];
					fields--;
				}
				remote_host = field[idx++];
				remote_port = field[idx++];
			} else
				print_usage(argv[0]);
			optind++;
			argv++;
			argc--;
			break;
		default:
			print_usage(argv[0]);
		}
	}
	if (!ifrname || !remote_host)
		print_usage(argv[0]);

	eth_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (eth_fd < 0) {
		fprintf(stderr, "socket: %m\n");
		return EXIT_FAILURE;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifrname);

	if (ioctl(eth_fd, SIOCGIFINDEX, &ifr) < 0){
		fprintf(stderr, "SIOCGIFINDEX: %m");
		return EXIT_FAILURE;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET; 
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(eth_fd, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
		fprintf(stderr, "bind: %m\n");
		return EXIT_FAILURE;
	}

	if (mtu > 0) {
		ifr.ifr_mtu = mtu;
		if (ioctl(eth_fd, SIOCSIFMTU, &ifr) < 0) {
			fprintf(stderr, "SIOCSIFMTU: %m\n");
			return EXIT_FAILURE;
		}
	}

	evutil_make_socket_nonblocking(eth_fd);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = local_host ? AF_UNSPEC : AF_INET;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_DGRAM;

	if (!local_port)
		local_port = "0";

	ret = getaddrinfo(local_host, local_port, &hints, &result);
	if (ret < 0) {
		fprintf(stderr, "%s:%s %s\n", local_host, local_port, gai_strerror(ret));
		return EXIT_FAILURE;
	}

	udp_fd = socket(result->ai_family, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
	if (udp_fd < 0) {
		fprintf(stderr, "socket: %m\n");
		return EXIT_FAILURE;
	}

	if (bind(udp_fd, result->ai_addr, result->ai_addrlen) < 0) {
		fprintf(stderr, "bind: %m\n");
		return EXIT_FAILURE;
	}
	freeaddrinfo(result);

	local_salen = sizeof(local_sa);
	if (getsockname(udp_fd, &local_sa, &local_salen) < 0) {
		fprintf(stderr, "getsockname: %m\n");
		return EXIT_FAILURE;
	}

	memset(&remote_addr, 0, sizeof(remote_addr));
	if (socks_port) {
		int fd;
		struct socks5_req req;
		unsigned short port;
		unsigned long lport;
		char buf[16];
		size_t len;

		if (!socks_host)
			socks_host = "localhost";

		lport = strtoul(remote_port, &endptr, 10);
		if (*endptr || lport > USHRT_MAX) {
			fprintf(stderr, "Invalid remote port %s\n", remote_port);
			return EXIT_FAILURE;
		}

		len = strlen(remote_host);
		if (len > 255) {
			fprintf(stderr, "Remote host %s too long\n", remote_host);
			return EXIT_FAILURE;
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		ret = getaddrinfo(socks_host, socks_port, &hints, &result);
		if (ret < 0) {
			fprintf(stderr, "%s\n", gai_strerror(ret));
			return EXIT_FAILURE;
		}

		fd = socket(result->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0) {
			fprintf(stderr, "socket: %m\n");
			return EXIT_FAILURE;
		}
		freeaddrinfo(result);

		if (connect(fd, result->ai_addr, result->ai_addrlen) < 0) {
			fprintf(stderr, "connect: %m\n");
			return EXIT_FAILURE;
		}

		/* "Authentication" */
		buf[0] = 5;
		buf[1] = 0;
		if (safe_write(fd, &buf, 2) < 0) {
			fprintf(stderr, "write: %m\n");
			return EXIT_FAILURE;
		}
		if (safe_read(fd, &buf, 2) <= 0) {
			fprintf(stderr, "read: %m\n");
			return EXIT_FAILURE;
		}
		if (buf[0] != 5 || buf[1] != 0) {
			fprintf(stderr, "socks connection error\n");
			return EXIT_FAILURE;
		}

		req.version = 5;
		req.reserved = 0;
		req.cmd = 3;			/* UDP associate */
		if (local_sa.sa_family == AF_INET)
			req.atyp = 1;
		else if (local_sa.sa_family == AF_INET6)
			req.atyp = 4;
		else
			return EXIT_FAILURE;

		if (safe_write(fd, &req, sizeof(req)) < 0) {
			fprintf(stderr, "write: %m\n");
			return EXIT_FAILURE;
		}

		if (local_sa.sa_family == AF_INET) {
			struct sockaddr_in *in = (struct sockaddr_in *) &local_sa;
			if (safe_write(fd, &in->sin_addr.s_addr, sizeof(in->sin_addr.s_addr)) < 0) {
				fprintf(stderr, "write: %m\n");
				return EXIT_FAILURE;
			}
			port = in->sin_port;
		} else if (local_sa.sa_family == AF_INET6) {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &local_sa;
			if (safe_write(fd, in6->sin6_addr.s6_addr, sizeof(in6->sin6_addr.s6_addr)) < 0) {
				fprintf(stderr, "write: %m\n");
				return EXIT_FAILURE;
			}
			port = in6->sin6_port;
		}

		if (safe_write(fd, &port, sizeof(port)) < 0) {
			fprintf(stderr, "write: %m\n");
			return EXIT_FAILURE;
		}

		if (safe_read(fd, &req, sizeof(req)) <= 0) {
			fprintf(stderr, "read: %m\n");
			return EXIT_FAILURE;
		}

		if (req.cmd != 0) {
			fprintf(stderr, "socks5 err: %hhu\n", req.cmd);
			return EXIT_FAILURE;
		}

		if (req.atyp == 1) {
			struct sockaddr_in *in = (struct sockaddr_in *) &remote_addr;
			in->sin_family = AF_INET;
			remote_addrlen = sizeof(*in);
			if (safe_read(fd, &in->sin_addr.s_addr, sizeof(in->sin_addr.s_addr)) <= 0) {
				fprintf(stderr, "read: %m\n");
				return EXIT_FAILURE;
			}
			if (safe_read(fd, &in->sin_port, sizeof(in->sin_port)) <= 0) {
				fprintf(stderr, "read: %m\n");
				return EXIT_FAILURE;
			}
		} else if (req.atyp == 4) {
			struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &remote_addr;
			in6->sin6_family = AF_INET6;
			remote_addrlen = sizeof(*in6);
			if (safe_read(fd, in6->sin6_addr.s6_addr, sizeof(in6->sin6_addr.s6_addr)) <= 0) {
				fprintf(stderr, "read: %m\n");
				return EXIT_FAILURE;
			}
			if (safe_read(fd, &in6->sin6_port, sizeof(in6->sin6_port)) <= 0) {
				fprintf(stderr, "read: %m\n");
				return EXIT_FAILURE;
			}
		} else {
			fprintf(stderr, "socks5 err\n");
			return EXIT_FAILURE;
		}

		if (inet_pton(AF_INET6, remote_host, buf) == 1) {
			udp_tx_buf[3] = 4;
			memcpy(udp_tx_buf + 4, buf, 16);
			*(unsigned short *)(udp_tx_buf + 4 + 16) = htons(lport);
			socks_hdr_len = 4 + 16 + 2;
		} else if (inet_pton(AF_INET, remote_host, buf) == 1) {
			udp_tx_buf[3] = 1;
			memcpy(udp_tx_buf + 4, buf, 4);
			*(unsigned short *)(udp_tx_buf + 4 + 4) = htons(lport);
			socks_hdr_len = 4 + 4 + 2;
		} else {
			udp_tx_buf[3] = 3;
			udp_tx_buf[4] = len;
			memcpy(udp_tx_buf + 5, remote_host, len);
			*(unsigned short *)(udp_tx_buf + 5 + len) = htons(lport);
			socks_hdr_len = 5 + len + 2;

		}

	} else {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;

		ret = getaddrinfo(remote_host, remote_port, &hints, &result);
		if (ret < 0) {
			fprintf(stderr, "%s\n", gai_strerror(ret));
			return ret;
		}

		memcpy(&remote_addr, result->ai_addr, result->ai_addrlen);
		remote_addrlen = result->ai_addrlen;
		freeaddrinfo(result);
	}

	if (connect(udp_fd, &remote_addr, remote_addrlen) < 0) {
		fprintf(stderr, "connect: %m\n");
		return EXIT_FAILURE;
	}

	ev = event_new(base, eth_fd, EV_READ | EV_PERSIST, eth_ready, (void *)udp_fd);
	event_add(ev, NULL);

	ev = event_new(base, udp_fd, EV_READ | EV_PERSIST, udp_ready, (void *)eth_fd);
	event_add(ev, NULL);

	if (promisc) {
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifrname);
		if (ioctl(eth_fd, SIOCGIFFLAGS, &ifr) < 0) {
			fprintf(stderr, "SIOCGIFFLAGS: %m\n");
			return EXIT_FAILURE;
		}

		if (!(ifr.ifr_flags & IFF_PROMISC)) {
			ifr.ifr_flags |= IFF_PROMISC;
			fd_for_die = eth_fd;
			ifr_name_for_die = ifrname;
			signal(SIGINT, die);
			signal(SIGQUIT, die);
			if (ioctl(eth_fd, SIOCSIFFLAGS, &ifr) < 0) {
				fprintf(stderr, "SIOCSIFFLAGS: %m\n");
				return EXIT_FAILURE;
			}
		}
	}

	event_base_dispatch(base);

	return 0;
}

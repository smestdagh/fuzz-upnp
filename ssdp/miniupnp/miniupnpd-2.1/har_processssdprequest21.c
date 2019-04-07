/* test harness for ProcessSSDPRequest function, based on minissdp.c */


/* $Id: minissdp.c,v 1.93 2018/04/22 19:36:58 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2018 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>
#include <err.h>

#ifdef IP_RECVIF
#include <sys/types.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/if_dl.h>
#endif

#if defined(ENABLE_IPV6) && defined(UPNP_STRICT)
#include <ifaddrs.h>
#endif /* defined(ENABLE_IPV6) && defined(UPNP_STRICT) */

#include <net/if.h>
#include <sys/queue.h>

/* dummy LAN address */
#define MYIFNAME  "eth0"
#define MYIFINDEX 0
#define MYADDRSTR "192.168.1.100"
#define MYADDRHEX 0x0101a8c0 /* 192.168.1.1   */
#define MYMASKHEX 0x00ffffff /* 255.255.255.0 */

/* dummy client address */
#define CLADDRHEX 0x6401a8c0 /* 192.168.1.100 */
#define CLPORTHEX 0x3930     /* 12345 */

/* structure and list for storing lan addresses
 * with ascii representation and mask */
struct lan_addr_s {
		char ifname[IFNAMSIZ];  /* example: eth0 */
		unsigned int index; /* use if_nametoindex() */
		char str[16];		/* example: 192.168.0.1 */
		struct in_addr addr, mask; /* ip/mask */
#ifdef MULTIPLE_EXTERNAL_IP
		char ext_ip_str[16];
		struct in_addr ext_ip_addr;
#endif
		LIST_ENTRY(lan_addr_s) list;
};
LIST_HEAD(lan_addr_list, lan_addr_s);

#define SSDP_PACKET_MAX_LEN 1024

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif /* MIN */


/* SSDP ip/port */
#define SSDP_PORT (1900)
#define SSDP_MCAST_ADDR ("239.255.255.250")
#define LL_SSDP_MCAST_ADDR "FF02::C"
#define SL_SSDP_MCAST_ADDR "FF05::C"
#define GL_SSDP_MCAST_ADDR "FF0E::C"

#define ROOTDESC_PATH "/rootDesc.xml"

#ifndef XSTR
#define XSTR(s) STR(s)
#define STR(s) #s
#endif /* XSTR */

#define UPNP_VERSION_MAJOR      1
#define UPNP_VERSION_MINOR      1
#define UPNP_VERSION_MAJOR_STR  XSTR(UPNP_VERSION_MAJOR)
#define UPNP_VERSION_MINOR_STR  XSTR(UPNP_VERSION_MINOR)
#define UPNP_VERSION_STRING "UPnP/" UPNP_VERSION_MAJOR_STR "." UPNP_VERSION_MINOR_STR
#define OS_VERSION "Linux/4.18.18-200.fc28.x86_64"
#define MINIUPNPD_VERSION "2.1"
#define MINIUPNPD_SERVER_STRING OS_VERSION " " UPNP_VERSION_STRING " MiniUPnPd/" MINIUPNPD_VERSION

char ipv6_addr_for_http_with_brackets[64];

char uuidvalue_igd[] = "uuid:00000000-0000-0000-0000-000000000000";
char uuidvalue_wan[] = "uuid:00000000-0000-0000-0000-000000000000";
char uuidvalue_wcd[] = "uuid:00000000-0000-0000-0000-000000000000";

unsigned int upnp_bootid = 1;		/* BOOTID.UPNP.ORG */
unsigned int upnp_configid = 1337;	/* CONFIGID.UPNP.ORG */

struct lan_addr_list lan_addrs;


int
get_src_for_route_to(const struct sockaddr * dst,
                     void * src, size_t * src_len,
                     int * index);

void
#ifdef ENABLE_HTTPS
ProcessSSDPRequest(int s,
                   unsigned short http_port, unsigned short https_port);
#else
ProcessSSDPRequest(int s, unsigned short http_port);
#endif

#ifdef ENABLE_HTTPS
void
ProcessSSDPData(int s, const char *bufr, int n,
                const struct sockaddr * sendername, int source_if,
                unsigned short http_port, unsigned short https_port);
#else
void
ProcessSSDPData(int s, const char *bufr, int n,
                const struct sockaddr * sendername, int source_if,
                unsigned short http_port);
#endif


int
sockaddr_to_string(const struct sockaddr * addr, char * str, size_t size)
{
	char buffer[64];
	unsigned short port = 0;
	int n = -1;

	switch(addr->sa_family)
	{
#ifdef AF_INET6
	case AF_INET6:
		if(inet_ntop(addr->sa_family,
		             &((struct sockaddr_in6 *)addr)->sin6_addr,
		             buffer, sizeof(buffer)) == NULL) {
			snprintf(buffer, sizeof(buffer), "inet_ntop: %s", strerror(errno));
		}
		port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
		if(((struct sockaddr_in6 *)addr)->sin6_scope_id > 0) {
			char ifname[IF_NAMESIZE];
			if(if_indextoname(((struct sockaddr_in6 *)addr)->sin6_scope_id, ifname) == NULL)
				strncpy(ifname, "ERROR", sizeof(ifname));
			n = snprintf(str, size, "[%s%%%s]:%hu", buffer, ifname, port);
		} else {
			n = snprintf(str, size, "[%s]:%hu", buffer, port);
		}
		break;
#endif /* AF_INET6 */
	case AF_INET:
		if(inet_ntop(addr->sa_family,
		             &((struct sockaddr_in *)addr)->sin_addr,
		             buffer, sizeof(buffer)) == NULL) {
			snprintf(buffer, sizeof(buffer), "inet_ntop: %s", strerror(errno));
		}
		port = ntohs(((struct sockaddr_in *)addr)->sin_port);
		n = snprintf(str, size, "%s:%hu", buffer, port);
		break;
#ifdef AF_LINK
	case AF_LINK:
		{
			struct sockaddr_dl * sdl = (struct sockaddr_dl *)addr;
			n = snprintf(str, size, "index=%hu type=%d %s",
			             sdl->sdl_index, sdl->sdl_type,
			             link_ntoa(sdl));
		}
		break;
#endif	/* AF_LINK */
	default:
		n = snprintf(str, size, "unknown address family %d", addr->sa_family);
	}
	return n;
}

struct lan_addr_s *
get_lan_for_peer(const struct sockaddr * peer)
{
	struct lan_addr_s * lan_addr = NULL;

#ifdef ENABLE_IPV6
	if(peer->sa_family == AF_INET6)
	{
		struct sockaddr_in6 * peer6 = (struct sockaddr_in6 *)peer;
		if(IN6_IS_ADDR_V4MAPPED(&peer6->sin6_addr))
		{
			struct in_addr peer_addr;
			memcpy(&peer_addr, &peer6->sin6_addr.s6_addr[12], 4);
			for(lan_addr = lan_addrs.lh_first;
			    lan_addr != NULL;
			    lan_addr = lan_addr->list.le_next)
			{
				if( (peer_addr.s_addr & lan_addr->mask.s_addr)
				   == (lan_addr->addr.s_addr & lan_addr->mask.s_addr))
					break;
			}
		}
		else
		{
			int index = -1;
			if(peer6->sin6_scope_id > 0)
				index = (int)peer6->sin6_scope_id;
/*			else
			{
				if(get_src_for_route_to(peer, NULL, NULL, &index) < 0)
					return NULL;
			}
			syslog(LOG_DEBUG, "%s looking for LAN interface index=%d",
			       "get_lan_for_peer()", index);
*/
			for(lan_addr = lan_addrs.lh_first;
			    lan_addr != NULL;
			    lan_addr = lan_addr->list.le_next)
			{
/*
				syslog(LOG_DEBUG,
				       "ifname=%s index=%u str=%s addr=%08x mask=%08x",
				       lan_addr->ifname, lan_addr->index,
				       lan_addr->str,
				       ntohl(lan_addr->addr.s_addr),
				       ntohl(lan_addr->mask.s_addr));
*/
				if(index == (int)lan_addr->index)
					break;
			}
		}
	}
	else if(peer->sa_family == AF_INET)
	{
#endif /* ENABLE_IPV6 */
		for(lan_addr = lan_addrs.lh_first;
		    lan_addr != NULL;
		    lan_addr = lan_addr->list.le_next)
		{
			if( (((const struct sockaddr_in *)peer)->sin_addr.s_addr & lan_addr->mask.s_addr)
			   == (lan_addr->addr.s_addr & lan_addr->mask.s_addr))
				break;
		}
#ifdef ENABLE_IPV6
	}
#endif /* ENABLE_IPV6 */

	return lan_addr;
}

/* Responds to a SSDP "M-SEARCH"
 * s :          socket to use
 * addr :       peer
 * st, st_len : ST: header
 * suffix :     suffix for USN: header
 * host, port : our HTTP host, port
 * delay :      in milli-seconds
 */
static void
SendSSDPResponse(int s, const struct sockaddr * addr,
                 const char * st, int st_len, const char * suffix,
                 const char * host, unsigned short http_port,
#ifdef ENABLE_HTTPS
                 unsigned short https_port,
#endif
                 const char * uuidvalue, unsigned int delay)
{
	int l, n;
	char buf[SSDP_PACKET_MAX_LEN];
	char addr_str[64];
	socklen_t addrlen;
	int st_is_uuid;
#ifdef ENABLE_HTTP_DATE
	char http_date[64];
	time_t t;
	struct tm tm;

	time(&t);
	gmtime_r(&t, &tm);
	strftime(http_date, sizeof(http_date),
		    "%a, %d %b %Y %H:%M:%S GMT", &tm);
#endif

	st_is_uuid = (st_len == (int)strlen(uuidvalue)) &&
	              (memcmp(uuidvalue, st, st_len) == 0);
	/*
	 * follow guideline from document "UPnP Device Architecture 1.0"
	 * uppercase is recommended.
	 * DATE: is recommended
	 * SERVER: OS/ver UPnP/1.0 miniupnpd/1.0
	 * - check what to put in the 'Cache-Control' header
	 *
	 * have a look at the document "UPnP Device Architecture v1.1 */
	l = snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n"
		"CACHE-CONTROL: max-age=120\r\n"
#ifdef ENABLE_HTTP_DATE
		"DATE: %s\r\n"
#endif
		"ST: %.*s%s\r\n"
		"USN: %s%s%.*s%s\r\n"
		"EXT:\r\n"
		"SERVER: " MINIUPNPD_SERVER_STRING "\r\n"
#ifndef RANDOMIZE_URLS
		"LOCATION: http://%s:%u" ROOTDESC_PATH "\r\n"
#ifdef ENABLE_HTTPS
		"SECURELOCATION.UPNP.ORG: https://%s:%u" ROOTDESC_PATH "\r\n"
#endif	/* ENABLE_HTTPS */
#else	/* RANDOMIZE_URLS */
		"LOCATION: http://%s:%u/%s" ROOTDESC_PATH "\r\n"
#ifdef ENABLE_HTTPS
		"SECURELOCATION.UPNP.ORG: https://%s:%u/%s" ROOTDESC_PATH "\r\n"
#endif	/* ENABLE_HTTPS */
#endif	/* RANDOMIZE_URLS */
		"OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n" /* UDA v1.1 */
		"01-NLS: %u\r\n" /* same as BOOTID. UDA v1.1 */
		"BOOTID.UPNP.ORG: %u\r\n" /* UDA v1.1 */
		"CONFIGID.UPNP.ORG: %u\r\n" /* UDA v1.1 */
		"\r\n",
#ifdef ENABLE_HTTP_DATE
		http_date,
#endif
		st_len, st, suffix,
		uuidvalue, st_is_uuid ? "" : "::",
		st_is_uuid ? 0 : st_len, st, suffix,
		host, (unsigned int)http_port,
#ifdef RANDOMIZE_URLS
		random_url,
#endif	/* RANDOMIZE_URLS */
#ifdef ENABLE_HTTPS
		host, (unsigned int)https_port,
#ifdef RANDOMIZE_URLS
		random_url,
#endif	/* RANDOMIZE_URLS */
#endif	/* ENABLE_HTTPS */
		upnp_bootid, upnp_bootid, upnp_configid);
	if(l<0)
	{
		warnx("%s: snprintf failed",
		       "SendSSDPResponse()");
		return;
	}
	else if((unsigned)l>=sizeof(buf))
	{
		warnx("%s: truncated output (%u>=%u)",
		       "SendSSDPResponse()", (unsigned)l, (unsigned)sizeof(buf));
		l = sizeof(buf) - 1;
	}
	addrlen = (addr->sa_family == AF_INET6)
	          ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    /* ADAPT THIS
	n = sendto_schedule(s, buf, l, 0,
	                    addr, addrlen, delay); */
	n = SSDP_PACKET_MAX_LEN;
	/* END ADAPT */
	sockaddr_to_string(addr, addr_str, sizeof(addr_str));
	printf("%s: %d bytes to %s ST: %.*s",
	       "SendSSDPResponse()",
	       n, addr_str, l, buf);
	if(n < 0)
	{
		warn("%s: sendto(udp): ",
		       "SendSSDPResponse()");
	}
}

static struct {
	const char * s;
	const int version;
	const char * uuid;
} const known_service_types[] =
{
	{"upnp:rootdevice", 0, uuidvalue_igd},
#ifdef IGD_V2
	{"urn:schemas-upnp-org:device:InternetGatewayDevice:", 2, uuidvalue_igd},
	{"urn:schemas-upnp-org:device:WANConnectionDevice:", 2, uuidvalue_wcd},
	{"urn:schemas-upnp-org:device:WANDevice:", 2, uuidvalue_wan},
	{"urn:schemas-upnp-org:service:WANIPConnection:", 2, uuidvalue_wcd},
	{"urn:schemas-upnp-org:service:DeviceProtection:", 1, uuidvalue_igd},
#ifdef ENABLE_6FC_SERVICE
	{"urn:schemas-upnp-org:service:WANIPv6FirewallControl:", 1, uuidvalue_wcd},
#endif
#else /* IGD_V2 */
	/* IGD v1 */
	{"urn:schemas-upnp-org:device:InternetGatewayDevice:", 1, uuidvalue_igd},
	{"urn:schemas-upnp-org:device:WANConnectionDevice:", 1, uuidvalue_wcd},
	{"urn:schemas-upnp-org:device:WANDevice:", 1, uuidvalue_wan},
	{"urn:schemas-upnp-org:service:WANIPConnection:", 1, uuidvalue_wcd},
#endif /* IGD_V2 */
	{"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:", 1, uuidvalue_wan},
#ifdef ADVERTISE_WANPPPCONN
	/* We use WAN IP Connection, not PPP connection,
	 * but buggy control points may try to use WanPPPConnection
	 * anyway */
	{"urn:schemas-upnp-org:service:WANPPPConnection:", 1, uuidvalue_wcd},
#endif /* ADVERTISE_WANPPPCONN */
#ifdef ENABLE_L3F_SERVICE
	{"urn:schemas-upnp-org:service:Layer3Forwarding:", 1, uuidvalue_igd},
#endif /* ENABLE_L3F_SERVICE */
/* we might want to support urn:schemas-wifialliance-org:device:WFADevice:1
 * urn:schemas-wifialliance-org:device:WFADevice:1
 * in the future */
	{0, 0, 0}
};

/* ProcessSSDPRequest()
 * process SSDP M-SEARCH requests and responds to them */
void
#ifdef ENABLE_HTTPS
ProcessSSDPRequest(int s, unsigned short http_port, unsigned short https_port)
#else
ProcessSSDPRequest(int s, unsigned short http_port)
#endif
{
	int n;
	char bufr[1500];
#ifdef ENABLE_IPV6
	struct sockaddr_in tempname =
		{ AF_INET, CLPORTHEX, { CLADDRHEX } };
	struct sockaddr_storage sendername;
	/*sendername = *((struct sockaddr_storage*) (&tempname));*/
	memset(&sendername, 0, sizeof(struct sockaddr_storage));
	memcpy(&sendername, &tempname, sizeof(struct sockaddr_in));
#else
	struct sockaddr_in sendername =
		{ AF_INET, CLPORTHEX, { CLADDRHEX } };
#endif
	int source_ifindex = -1;
#ifdef IP_PKTINFO
	char cmbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct iovec iovec = {
		.iov_base = bufr,
		.iov_len = sizeof(bufr)
	};
	struct msghdr mh = {
		.msg_name = &sendername,
		.msg_namelen = sizeof(sendername),
		.msg_iov = &iovec,
		.msg_iovlen = 1,
		.msg_control = cmbuf,
		.msg_controllen = sizeof(cmbuf)
	};
	struct cmsghdr *cmptr;
#endif /* IP_PKTINFO */
#ifdef IP_RECVIF
	char cmbuf[CMSG_SPACE(sizeof(struct sockaddr_dl))];
	struct iovec iovec = {
		.iov_base = bufr,
		.iov_len = sizeof(bufr)
	};
	struct msghdr mh = {
		.msg_name = &sendername,
		.msg_namelen = sizeof(sendername),
		.msg_iov = &iovec,
		.msg_iovlen = 1,
		.msg_control = cmbuf,
		.msg_controllen = sizeof(cmbuf)
	};
	struct cmsghdr *cmptr;
#endif /* IP_RECVIF */

    /* read data from stdin */
    ssize_t res = read(0, bufr, sizeof(bufr));
    if (res < 0) { return; } else { n = res; }

/*
#if defined(IP_RECVIF) || defined(IP_PKTINFO)
	n = recvmsg(s, &mh, 0);
#else
	socklen_t len_r;
	len_r = sizeof(sendername);
	n = recvfrom(s, bufr, sizeof(bufr), 0,
	             (struct sockaddr *)&sendername, &len_r);
#endif *//* defined(IP_RECVIF) || defined(IP_PKTINFO) */
	if(n < 0)
	{
		/* EAGAIN, EWOULDBLOCK, EINTR : silently ignore (try again next time)
		 * other errors : log to LOG_ERR */
		if(errno != EAGAIN &&
		   errno != EWOULDBLOCK &&
		   errno != EINTR)
		{
			warnx("recvfrom(udp)");
		}
		return;
	}

#if defined(IP_RECVIF) || defined(IP_PKTINFO)
	for(cmptr = CMSG_FIRSTHDR(&mh); cmptr != NULL; cmptr = CMSG_NXTHDR(&mh, cmptr))
	{
		printf("level=%d type=%d", cmptr->cmsg_level, cmptr->cmsg_type);
#ifdef IP_PKTINFO
		if(cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_PKTINFO)
		{
			struct in_pktinfo * pi;	/* fields : ifindex, spec_dst, addr */
			pi = (struct in_pktinfo *)CMSG_DATA(cmptr);
			printf("ifindex = %u  %s", pi->ipi_ifindex, inet_ntoa(pi->ipi_spec_dst));
			source_ifindex = pi->ipi_ifindex;
		}
#endif /* IP_PKTINFO */
#if defined(ENABLE_IPV6) && defined(IPV6_RECVPKTINFO)
		if(cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == IPV6_RECVPKTINFO)
		{
			struct in6_pktinfo * pi6;	/* fields : ifindex, addr */
			pi6 = (struct in6_pktinfo *)CMSG_DATA(cmptr);
			printf("ifindex = %u", pi6->ipi6_ifindex);
			source_ifindex = pi6->ipi6_ifindex;
		}
#endif /* defined(ENABLE_IPV6) && defined(IPV6_RECVPKTINFO) */
#ifdef IP_RECVIF
		if(cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
		{
			struct sockaddr_dl *sdl;	/* fields : len, family, index, type, nlen, alen, slen, data */
			sdl = (struct sockaddr_dl *)CMSG_DATA(cmptr);
			printf("sdl_index = %d  %s", sdl->sdl_index, link_ntoa(sdl));
			source_ifindex = sdl->sdl_index;
		}
#endif /* IP_RECVIF */
	}
#endif /* defined(IP_RECVIF) || defined(IP_PKTINFO) */
#ifdef ENABLE_HTTPS
	ProcessSSDPData(s, bufr, n, (struct sockaddr *)&sendername, source_ifindex,
	                http_port, https_port);
#else
	ProcessSSDPData(s, bufr, n, (struct sockaddr *)&sendername, source_ifindex,
	                http_port);
#endif

}

#ifdef ENABLE_HTTPS
void
ProcessSSDPData(int s, const char *bufr, int n,
                const struct sockaddr * sender, int source_if,
                unsigned short http_port, unsigned short https_port)
#else
void
ProcessSSDPData(int s, const char *bufr, int n,
                const struct sockaddr * sender, int source_if,
                unsigned short http_port)
#endif
{
	int i, l;
	struct lan_addr_s * lan_addr = NULL;
	const char * st = NULL;
	int st_len = 0;
	int st_ver = 0;
	char sender_str[64];
	char ver_str[4];
	const char * announced_host = NULL;
#ifdef UPNP_STRICT
#ifdef ENABLE_IPV6
	char announced_host_buf[64];
#endif
#endif
#if defined(UPNP_STRICT) || defined(DELAY_MSEARCH_RESPONSE)
	int mx_value = -1;
#endif
	unsigned int delay = 50; /* Non-zero default delay to prevent flooding */
	/* UPnP Device Architecture v1.1.  1.3.3 Search response :
	 * Devices responding to a multicast M-SEARCH SHOULD wait a random period
	 * of time between 0 seconds and the number of seconds specified in the
	 * MX field value of the search request before responding, in order to
	 * avoid flooding the requesting control point with search responses
	 * from multiple devices. If the search request results in the need for
	 * a multiple part response from the device, those multiple part
	 * responses SHOULD be spread at random intervals through the time period
	 * from 0 to the number of seconds specified in the MX header field. */
	char atoi_buffer[8];

	/* get the string representation of the sender address */
	sockaddr_to_string(sender, sender_str, sizeof(sender_str));
	lan_addr = get_lan_for_peer(sender);
	if(source_if >= 0)
	{
		if(lan_addr != NULL)
		{
			if(lan_addr->index != (unsigned)source_if && lan_addr->index != 0)
			{
				warnx("interface index not matching %u != %d", lan_addr->index, source_if);
			}
		}
		else
		{
			/* use the interface index */
			for(lan_addr = lan_addrs.lh_first;
			    lan_addr != NULL;
			    lan_addr = lan_addr->list.le_next)
			{
				if(lan_addr->index == (unsigned)source_if)
					break;
			}
		}
	}
	if(lan_addr == NULL)
	{
		warnx("SSDP packet sender %s (if_index=%d) not from a LAN, ignoring",
		       sender_str, source_if);
		return;
	}

	if(memcmp(bufr, "NOTIFY", 6) == 0)
	{
		/* ignore NOTIFY packets. We could log the sender and device type */
		return;
	}
	else if(memcmp(bufr, "M-SEARCH", 8) == 0)
	{
		i = 0;
		while(i < n)
		{
			while((i < n - 1) && (bufr[i] != '\r' || bufr[i+1] != '\n'))
				i++;
			i += 2;
			if((i < n - 3) && (strncasecmp(bufr+i, "st:", 3) == 0))
			{
				st = bufr+i+3;
				st_len = 0;
				while((*st == ' ' || *st == '\t') && (st < bufr + n))
					st++;
				while((st + st_len < bufr + n)
				      && (st[st_len]!='\r' && st[st_len]!='\n'))
					st_len++;
				l = st_len;
				while(l > 0 && st[l-1] != ':')
					l--;
				memset(atoi_buffer, 0, sizeof(atoi_buffer));
				memcpy(atoi_buffer, st + l, MIN((int)(sizeof(atoi_buffer) - 1), st_len - l));
				st_ver = atoi(atoi_buffer);
				printf("ST: %.*s (ver=%d)", st_len, st, st_ver);
			}
#if defined(UPNP_STRICT) || defined(DELAY_MSEARCH_RESPONSE)
			else if((i < n - 3) && (strncasecmp(bufr+i, "mx:", 3) == 0))
			{
				const char * mx;
				int mx_len;
				mx = bufr+i+3;
				mx_len = 0;
				while((mx < bufr + n) && (*mx == ' ' || *mx == '\t'))
					mx++;
				while((mx + mx_len < bufr + n)
				      && (mx[mx_len]!='\r' && mx[mx_len]!='\n'))
					mx_len++;
				memset(atoi_buffer, 0, sizeof(atoi_buffer));
				memcpy(atoi_buffer, mx, MIN((int)(sizeof(atoi_buffer) - 1), mx_len));
				mx_value = atoi(atoi_buffer);
				printf("MX: %.*s (value=%d)", mx_len, mx, mx_value);
			}
#endif /* defined(UPNP_STRICT) || defined(DELAY_MSEARCH_RESPONSE) */
#if defined(UPNP_STRICT)
			/* Fix UDA-1.2.10 Man header empty or invalid */
			else if((i < n - 4) && (strncasecmp(bufr+i, "man:", 3) == 0))
			{
				const char * man;
				int man_len;
				man = bufr+i+4;
				man_len = 0;
				while((man < bufr + n) && (*man == ' ' || *man == '\t'))
					man++;
				while((man + man_len < bufr + n)
					  && (man[man_len]!='\r' && man[man_len]!='\n'))
					man_len++;
				if((man_len < 15) || (strncmp(man, "\"ssdp:discover\"", 15) != 0)) {
					printf("ignoring SSDP packet MAN empty or invalid header");
					return;
				}
			}
#endif /* defined(UPNP_STRICT) */
		}
#ifdef UPNP_STRICT
		/* For multicast M-SEARCH requests, if the search request does
		 * not contain an MX header field, the device MUST silently
		 * discard and ignore the search request. */
		if(mx_value < 0) {
			printf("ignoring SSDP packet missing MX: header");
			return;
		} else if(mx_value > 5) {
			/* If the MX header field specifies a field value greater
			 * than 5, the device SHOULD assume that it contained the
			 * value 5 or less. */
			mx_value = 5;
		}
#elif defined(DELAY_MSEARCH_RESPONSE)
		if(mx_value < 0) {
			mx_value = 1;
		} else if(mx_value > 5) {
			/* If the MX header field specifies a field value greater
			 * than 5, the device SHOULD assume that it contained the
			 * value 5 or less. */
			mx_value = 5;
		}
#endif
		if(st && (st_len > 0))
		{
			printf("SSDP M-SEARCH from %s ST: %.*s",
			       sender_str, st_len, st);
			/* find in which sub network the client is */
			if(sender->sa_family == AF_INET)
			{
				if (lan_addr == NULL)
				{
					errx(LOG_ERR,
					       "Can't find in which sub network the client %s is",
					       sender_str);
					return;
				}
				announced_host = lan_addr->str;
			}
#ifdef ENABLE_IPV6
			else
			{
				/* IPv6 address with brackets */
#ifdef UPNP_STRICT
				int index;
				struct in6_addr addr6;
				size_t addr6_len = sizeof(addr6);
				/* retrieve the IPv6 address which
				 * will be used locally to reach sender */
				memset(&addr6, 0, sizeof(addr6));
				if(IN6_IS_ADDR_LINKLOCAL(&(((struct sockaddr_in6 *)sender)->sin6_addr))) {
					get_link_local_addr(((struct sockaddr_in6 *)sender)->sin6_scope_id, &addr6);
				} else if(get_src_for_route_to (sender, &addr6, &addr6_len, &index) < 0) {
					warnx("get_src_for_route_to() failed, using %s", ipv6_addr_for_http_with_brackets);
					announced_host = ipv6_addr_for_http_with_brackets;
				}
				if(announced_host == NULL) {
					if(inet_ntop(AF_INET6, &addr6,
					             announced_host_buf+1,
					             sizeof(announced_host_buf) - 2)) {
						announced_host_buf[0] = '[';
						i = strlen(announced_host_buf);
						if(i < (int)sizeof(announced_host_buf) - 1) {
							announced_host_buf[i] = ']';
							announced_host_buf[i+1] = '\0';
						} else {
							printf("cannot suffix %s with ']'",
							       announced_host_buf);
						}
						announced_host = announced_host_buf;
					} else {
						printf("inet_ntop() failed");
						announced_host = ipv6_addr_for_http_with_brackets;
					}
				}
#else
				announced_host = ipv6_addr_for_http_with_brackets;
#endif
			}
#endif
			/* Responds to request with a device as ST header */
			for(i = 0; known_service_types[i].s; i++)
			{
				l = (int)strlen(known_service_types[i].s);
				if(l<=st_len && (0 == memcmp(st, known_service_types[i].s, l))
#ifdef UPNP_STRICT
				   && (st_ver <= known_service_types[i].version)
		/* only answer for service version lower or equal of supported one */
#endif
				   )
				{
					/* SSDP_RESPOND_SAME_VERSION :
					 * response is urn:schemas-upnp-org:service:WANIPConnection:1 when
					 * M-SEARCH included urn:schemas-upnp-org:service:WANIPConnection:1
					 * else the implemented versions is included in the response
					 *
					 * From UPnP Device Architecture v1.1 :
					 * 1.3.2 [...] Updated versions of device and service types
					 * are REQUIRED to be fully backward compatible with
					 * previous versions. Devices MUST respond to M-SEARCH
					 * requests for any supported version. For example, if a
					 * device implements “urn:schemas-upnporg:service:xyz:2”,
					 * it MUST respond to search requests for both that type
					 * and “urn:schemas-upnp-org:service:xyz:1”. The response
					 * MUST specify the same version as was contained in the
					 * search request. [...] */
#ifndef SSDP_RESPOND_SAME_VERSION
					if(i==0)
						ver_str[0] = '\0';
					else
						snprintf(ver_str, sizeof(ver_str), "%d", known_service_types[i].version);
#endif
					printf("Single search found");
#ifdef DELAY_MSEARCH_RESPONSE
					delay = random() / (1 + RAND_MAX / (1000 * mx_value));
#endif
					SendSSDPResponse(s, sender,
#ifdef SSDP_RESPOND_SAME_VERSION
					                 st, st_len, "",
#else
					                 known_service_types[i].s, l, ver_str,
#endif
					                 announced_host, http_port,
#ifdef ENABLE_HTTPS
					                 https_port,
#endif
					                 known_service_types[i].uuid,
					                 delay);
					break;
				}
			}
			/* Responds to request with ST: ssdp:all */
			/* strlen("ssdp:all") == 8 */
			if(st_len==8 && (0 == memcmp(st, "ssdp:all", 8)))
			{
#ifdef DELAY_MSEARCH_RESPONSE
				unsigned int delay_increment = (mx_value * 1000) / 15;
#endif
				printf("ssdp:all found");
				for(i=0; known_service_types[i].s; i++)
				{
#ifdef DELAY_MSEARCH_RESPONSE
					delay += delay_increment;
#endif
					if(i==0)
						ver_str[0] = '\0';
					else
						snprintf(ver_str, sizeof(ver_str), "%d", known_service_types[i].version);
					l = (int)strlen(known_service_types[i].s);
					SendSSDPResponse(s, sender,
					                 known_service_types[i].s, l, ver_str,
					                 announced_host, http_port,
#ifdef ENABLE_HTTPS
					                 https_port,
#endif
					                 known_service_types[i].uuid,
					                 delay);
				}
				/* also answer for uuid */
#ifdef DELAY_MSEARCH_RESPONSE
					delay += delay_increment;
#endif
				SendSSDPResponse(s, sender, uuidvalue_igd, strlen(uuidvalue_igd), "",
				                 announced_host, http_port,
#ifdef ENABLE_HTTPS
				                 https_port,
#endif
				                 uuidvalue_igd, delay);
#ifdef DELAY_MSEARCH_RESPONSE
					delay += delay_increment;
#endif
				SendSSDPResponse(s, sender, uuidvalue_wan, strlen(uuidvalue_wan), "",
				                 announced_host, http_port,
#ifdef ENABLE_HTTPS
				                 https_port,
#endif
				                 uuidvalue_wan, delay);
#ifdef DELAY_MSEARCH_RESPONSE
					delay += delay_increment;
#endif
				SendSSDPResponse(s, sender, uuidvalue_wcd, strlen(uuidvalue_wcd), "",
				                 announced_host, http_port,
#ifdef ENABLE_HTTPS
				                 https_port,
#endif
				                 uuidvalue_wcd, delay);
			}
			/* responds to request by UUID value */
			l = (int)strlen(uuidvalue_igd);
			if(l==st_len)
			{
#ifdef DELAY_MSEARCH_RESPONSE
				delay = random() / (1 + RAND_MAX / (1000 * mx_value));
#endif
				if(0 == memcmp(st, uuidvalue_igd, l))
				{
					printf("ssdp:uuid (IGD) found");
					SendSSDPResponse(s, sender, st, st_len, "",
					                 announced_host, http_port,
#ifdef ENABLE_HTTPS
					                 https_port,
#endif
					                 uuidvalue_igd, delay);
				}
				else if(0 == memcmp(st, uuidvalue_wan, l))
				{
					printf("ssdp:uuid (WAN) found");
					SendSSDPResponse(s, sender, st, st_len, "",
					                 announced_host, http_port,
#ifdef ENABLE_HTTPS
					                 https_port,
#endif
					                 uuidvalue_wan, delay);
				}
				else if(0 == memcmp(st, uuidvalue_wcd, l))
				{
					printf("ssdp:uuid (WCD) found");
					SendSSDPResponse(s, sender, st, st_len, "",
					                 announced_host, http_port,
#ifdef ENABLE_HTTPS
					                 https_port,
#endif
					                 uuidvalue_wcd, delay);
				}
			}
		}
		else
		{
			warnx("Invalid SSDP M-SEARCH from %s", sender_str);
		}
	}
	else
	{
		warnx("Unknown udp packet received from %s", sender_str);
	}
}

int main() {
   struct lan_addr_s * lan_addr = 
	      (struct lan_addr_s *) malloc(sizeof(struct lan_addr_s));
   memset(lan_addr, 0, sizeof(struct lan_addr_s));
   strncpy((char*)&(lan_addr->ifname), MYIFNAME, IFNAMSIZ);
   lan_addr->index  = MYIFINDEX;
   strncpy((char*)&(lan_addr->str), MYADDRSTR, 16);
   lan_addr->addr   = (struct in_addr) { MYADDRHEX };
   lan_addr->mask   = (struct in_addr) { MYMASKHEX };
   LIST_INIT(&lan_addrs);
   LIST_INSERT_HEAD(&lan_addrs, lan_addr, list);
   ProcessSSDPRequest(1, 4321);
   return 0;
}

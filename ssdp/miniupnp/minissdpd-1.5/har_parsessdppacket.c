/* test harness for ParseSSDPPacket function, based on minissdpd.c *


/* $Id: minissdpd.c,v 1.51 2016/01/13 15:22:11 nanard Exp $ */
/* MiniUPnP project
 * (c) 2007-2016 Thomas Bernard
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/*#include "config.h"*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>
#include <sys/queue.h>
#include <net/if.h>
#include <err.h>

/* dummy LAN address */
#define MYIFNAME  "eth0"
#define MYIFINDEX 0
#define MYADDRSTR "192.168.1.100"
#define MYADDRHEX 0x0101a8c0 /* 192.168.1.1   */
#define MYMASKHEX 0x00ffffff /* 255.255.255.0 */

/* dummy client address */
#define CLADDRHEX 0x6401a8c0 /* 192.168.1.100 */
#define CLADDR6HEX { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a } /* fe80::a */
#define CLPORTHEX 0x3930     /* 12345 */

#define RESPONSE_BUFFER_SIZE (1024 * 4)

#define CODELENGTH(n, p) if(n>=268435456) *(p++) = (n >> 28) | 0x80; \
                         if(n>=2097152) *(p++) = (n >> 21) | 0x80; \
                         if(n>=16384) *(p++) = (n >> 14) | 0x80; \
                         if(n>=128) *(p++) = (n >> 7) | 0x80; \
                         *(p++) = n & 0x7f;

/* structure and list for storing lan addresses
 * with ascii representation and mask */
struct lan_addr_s {
        char ifname[IFNAMSIZ];  /* example: eth0 */
#ifdef ENABLE_IPV6
        unsigned int index;             /* use if_nametoindex() */
#endif /* ENABLE_IPV6 */
        char str[16];   /* example: 192.168.0.1 */
        struct in_addr addr, mask;      /* ip/mask */
        LIST_ENTRY(lan_addr_s) list;
};
LIST_HEAD(lan_addr_list, lan_addr_s);


/* current request management stucture */
struct reqelem {
	int socket;
	int is_notify;	/* has subscribed to notifications */
	LIST_ENTRY(reqelem) entries;
	unsigned char * output_buffer;
	int output_buffer_offset;
	int output_buffer_len;
};

/* device data structures */
struct header {
	const char * p; /* string pointer */
	int l;          /* string length */
};

#define HEADER_NT	0
#define HEADER_USN	1
#define HEADER_LOCATION	2

struct device {
	struct device * next;
	time_t t;                 /* validity time */
	struct header headers[3]; /* NT, USN and LOCATION headers */
	char data[];
};

/* Services stored for answering to M-SEARCH */
struct service {
	char * st;	/* Service type */
	char * usn;	/* Unique identifier */
	char * server;	/* Server string */
	char * location;	/* URL */
	LIST_ENTRY(service) entries;
};
LIST_HEAD(servicehead, service) servicelisthead;

#define NTS_SSDP_ALIVE	1
#define NTS_SSDP_BYEBYE	2
#define NTS_SSDP_UPDATE	3

/* request types */
enum request_type {
	MINISSDPD_GET_VERSION = 0,
	MINISSDPD_SEARCH_TYPE = 1,
	MINISSDPD_SEARCH_USN = 2,
	MINISSDPD_SEARCH_ALL = 3,
	MINISSDPD_SUBMIT = 4,
	MINISSDPD_NOTIF = 5
};

/* discovered device list kept in memory */
struct device * devlist = 0;

/* bootid and configid */
unsigned int upnp_bootid = 1;
unsigned int upnp_configid = 1337;

/* LAN interfaces/addresses */
struct lan_addr_list lan_addrs;

/* connected clients */
LIST_HEAD(reqstructhead, reqelem) reqlisthead;

/* functions prototypes */

#define NOTIF_NEW    1
#define NOTIF_UPDATE 2
#define NOTIF_REMOVE 3
static void
sendNotifications(int notif_type, const struct device * dev, const struct service * serv);

/* functions */

int
sockaddr_to_string(const struct sockaddr * addr, char * str, size_t size)
{
        char buffer[64];
        unsigned short port = 0;
        int n = -1;

        switch(addr->sa_family)
        {
        case AF_INET6:
                inet_ntop(addr->sa_family,
                          &((struct sockaddr_in6 *)addr)->sin6_addr,
                          buffer, sizeof(buffer));
                port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
                n = snprintf(str, size, "[%s]:%hu", buffer, port);
                break;
        case AF_INET:
                inet_ntop(addr->sa_family,
                          &((struct sockaddr_in *)addr)->sin_addr,
                          buffer, sizeof(buffer));
                port = ntohs(((struct sockaddr_in *)addr)->sin_port);
                n = snprintf(str, size, "%s:%hu", buffer, port);
                break;
#ifdef AF_LINK
#if defined(__sun)
                /* solaris does not seem to have link_ntoa */
                /* #define link_ntoa _link_ntoa */
#define link_ntoa(x) "dummy-link_ntoa"
#endif
        case AF_LINK:
                {
                        struct sockaddr_dl * sdl = (struct sockaddr_dl *)addr;
                        n = snprintf(str, size, "index=%hu type=%d %s",
                                     sdl->sdl_index, sdl->sdl_type,
                                     link_ntoa(sdl));
                }
                break;
#endif
        default:
                n = snprintf(str, size, "unknown address family %d", addr->sa_family);
        }
        return n;
}

static int
write_buffer(struct reqelem * req)
{
	if(req->output_buffer && req->output_buffer_len > 0) {
		int n = write(req->socket,
		              req->output_buffer + req->output_buffer_offset,
		              req->output_buffer_len);
		if(n >= 0) {
			req->output_buffer_offset += n;
			req->output_buffer_len -= n;
		} else if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
			return 0;
		}
		return n;
	} else {
		return 0;
	}
}

static int
add_to_buffer(struct reqelem * req, const unsigned char * data, int len)
{
	unsigned char * tmp;
	if(req->output_buffer_offset > 0) {
		memmove(req->output_buffer, req->output_buffer + req->output_buffer_offset, req->output_buffer_len);
		req->output_buffer_offset = 0;
	}
	tmp = realloc(req->output_buffer, req->output_buffer_len + len);
	if(tmp == NULL) {
		warnx("%s: failed to allocate %d bytes",
		       __func__, req->output_buffer_len + len);
		return -1;
	}
	req->output_buffer = tmp;
	memcpy(req->output_buffer + req->output_buffer_len, data, len);
	req->output_buffer_len += len;
	return len;
}

static int
write_or_buffer(struct reqelem * req, const unsigned char * data, int len)
{
	if(write_buffer(req) < 0)
		return -1;
	if(req->output_buffer && req->output_buffer_len > 0) {
		return add_to_buffer(req, data, len);
	} else {
		int n = write(req->socket, data, len);
		if(n == len)
			return len;
		if(n < 0) {
			if(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN) {
				n = add_to_buffer(req, data, len);
				if(n < 0) return n;
			} else {
				return n;
			}
		} else {
			n = add_to_buffer(req, data + n, len - n);
			if(n < 0) return n;
		}
	}
	return len;
}

static const char *
nts_to_str(int nts)
{
	switch(nts)
	{
	case NTS_SSDP_ALIVE:
		return "ssdp:alive";
	case NTS_SSDP_BYEBYE:
		return "ssdp:byebye";
	case NTS_SSDP_UPDATE:
		return "ssdp:update";
	}
	return "unknown";
}

/* updateDevice() :
 * adds or updates the device to the list.
 * return value :
 *   0 : the device was updated (or nothing done)
 *   1 : the device was new    */
static int
updateDevice(const struct header * headers, time_t t)
{
	struct device ** pp = &devlist;
	struct device * p = *pp;	/* = devlist; */
	while(p)
	{
		if(  p->headers[HEADER_NT].l == headers[HEADER_NT].l
		  && (0==memcmp(p->headers[HEADER_NT].p, headers[HEADER_NT].p, headers[HEADER_NT].l))
		  && p->headers[HEADER_USN].l == headers[HEADER_USN].l
		  && (0==memcmp(p->headers[HEADER_USN].p, headers[HEADER_USN].p, headers[HEADER_USN].l)) )
		{
			/*printf("found! %d\n", (int)(t - p->t));*/
			warnx("device updated : %.*s", headers[HEADER_USN].l, headers[HEADER_USN].p);
			p->t = t;
			/* update Location ! */
			if(headers[HEADER_LOCATION].l > p->headers[HEADER_LOCATION].l)
			{
				struct device * tmp;
				tmp = realloc(p, sizeof(struct device)
				    + headers[0].l+headers[1].l+headers[2].l);
				if(!tmp)	/* allocation error */
				{
					warnx("updateDevice() : memory allocation error");
					free(p);
					return 0;
				}
				p = tmp;
				*pp = p;
			}
			memcpy(p->data + p->headers[0].l + p->headers[1].l,
			       headers[2].p, headers[2].l);
			/* TODO : check p->headers[HEADER_LOCATION].l */
			return 0;
		}
		pp = &p->next;
		p = *pp;	/* p = p->next; */
	}
	warnx("new device discovered : %.*s",
	       headers[HEADER_USN].l, headers[HEADER_USN].p);
	/* add */
	{
		char * pc;
		int i;
		p = malloc(  sizeof(struct device)
		           + headers[0].l+headers[1].l+headers[2].l );
		if(!p) {
			warnx("updateDevice(): cannot allocate memory");
			return -1;
		}
		p->next = devlist;
		p->t = t;
		pc = p->data;
		for(i = 0; i < 3; i++)
		{
			p->headers[i].p = pc;
			p->headers[i].l = headers[i].l;
			memcpy(pc, headers[i].p, headers[i].l);
			pc += headers[i].l;
		}
		devlist = p;
		sendNotifications(NOTIF_NEW, p, NULL);
	}
	return 1;
}

/* removeDevice() :
 * remove a device from the list
 * return value :
 *    0 : no device removed
 *   -1 : device removed */
static int
removeDevice(const struct header * headers)
{
	struct device ** pp = &devlist;
	struct device * p = *pp;	/* = devlist */
	while(p)
	{
		if(  p->headers[HEADER_NT].l == headers[HEADER_NT].l
		  && (0==memcmp(p->headers[HEADER_NT].p, headers[HEADER_NT].p, headers[HEADER_NT].l))
		  && p->headers[HEADER_USN].l == headers[HEADER_USN].l
		  && (0==memcmp(p->headers[HEADER_USN].p, headers[HEADER_USN].p, headers[HEADER_USN].l)) )
		{
			warnx("remove device : %.*s", headers[HEADER_USN].l, headers[HEADER_USN].p);
			sendNotifications(NOTIF_REMOVE, p, NULL);
			*pp = p->next;
			free(p);
			return -1;
		}
		pp = &p->next;
		p = *pp;	/* p = p->next; */
	}
	warnx("device not found for removing : %.*s", headers[HEADER_USN].l, headers[HEADER_USN].p);
	return 0;
}

/* sent notifications to client having subscribed */
static void
sendNotifications(int notif_type, const struct device * dev, const struct service * serv)
{
	struct reqelem * req;
	unsigned int m;
	unsigned char rbuf[RESPONSE_BUFFER_SIZE];
	unsigned char * rp;

	for(req = reqlisthead.lh_first; req; req = req->entries.le_next) {
		if(!req->is_notify) continue;
		rbuf[0] = '\xff'; /* special code for notifications */
		rbuf[1] = (unsigned char)notif_type;
		rbuf[2] = 0;
		rp = rbuf + 3;
		if(dev) {
			/* response :
			 * 1 - Location
			 * 2 - NT (device/service type)
			 * 3 - usn */
			m = dev->headers[HEADER_LOCATION].l;
			CODELENGTH(m, rp);
			memcpy(rp, dev->headers[HEADER_LOCATION].p, dev->headers[HEADER_LOCATION].l);
			rp += dev->headers[HEADER_LOCATION].l;
			m = dev->headers[HEADER_NT].l;
			CODELENGTH(m, rp);
			memcpy(rp, dev->headers[HEADER_NT].p, dev->headers[HEADER_NT].l);
			rp += dev->headers[HEADER_NT].l;
			m = dev->headers[HEADER_USN].l;
			CODELENGTH(m, rp);
			memcpy(rp, dev->headers[HEADER_USN].p, dev->headers[HEADER_USN].l);
			rp += dev->headers[HEADER_USN].l;
			rbuf[2]++;
		}
		if(serv) {
			/* response :
			 * 1 - Location
			 * 2 - NT (device/service type)
			 * 3 - usn */
			m = strlen(serv->location);
			CODELENGTH(m, rp);
			memcpy(rp, serv->location, m);
			rp += m;
			m = strlen(serv->st);
			CODELENGTH(m, rp);
			memcpy(rp, serv->st, m);
			rp += m;
			m = strlen(serv->usn);
			CODELENGTH(m, rp);
			memcpy(rp, serv->usn, m);
			rp += m;
			rbuf[2]++;
		}
		if(rbuf[2] > 0) {
			if(write_or_buffer(req, rbuf, rp - rbuf) < 0) {
				warnx("(s=%d) write: %m", req->socket);
				/*goto error;*/
			}
		}
	}
}

/* SendSSDPMSEARCHResponse() :
 * build and send response to M-SEARCH SSDP packets. */
static void
SendSSDPMSEARCHResponse(int s, const struct sockaddr * sockname,
                        const char * st, const char * usn,
                        const char * server, const char * location)
{
	printf("%s", "received M-SEARCH request\n");
}

/* Process M-SEARCH requests */
static void
processMSEARCH(int s, const char * st, int st_len,
               const struct sockaddr * addr)
{
	struct service * serv;
#ifdef ENABLE_IPV6
	char buf[64];
#endif /* ENABLE_IPV6 */

	if(!st || st_len==0)
		return;
#ifdef ENABLE_IPV6
	sockaddr_to_string(addr, buf, sizeof(buf));
	warnx("SSDP M-SEARCH from %s ST:%.*s",
	       buf, st_len, st);
#else	/* ENABLE_IPV6 */
	warnx("SSDP M-SEARCH from %s:%d ST: %.*s",
	       inet_ntoa(((const struct sockaddr_in *)addr)->sin_addr),
	       ntohs(((const struct sockaddr_in *)addr)->sin_port),
	       st_len, st);
#endif	/* ENABLE_IPV6 */
	if(st_len==8 && (0==memcmp(st, "ssdp:all", 8))) {
		/* send a response for all services */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			SendSSDPMSEARCHResponse(s, addr,
			                        serv->st, serv->usn,
			                        serv->server, serv->location);
		}
	} else if(st_len > 5 && (0==memcmp(st, "uuid:", 5))) {
		/* find a matching UUID value */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			if(0 == strncmp(serv->usn, st, st_len)) {
				SendSSDPMSEARCHResponse(s, addr,
				                        serv->st, serv->usn,
				                        serv->server, serv->location);
			}
		}
	} else {
		/* find matching services */
		/* remove version at the end of the ST string */
		if(st[st_len-2]==':' && isdigit(st[st_len-1]))
			st_len -= 2;
		/* answer for each matching service */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			if(0 == strncmp(serv->st, st, st_len)) {
				SendSSDPMSEARCHResponse(s, addr,
				                        serv->st, serv->usn,
				                        serv->server, serv->location);
			}
		}
	}
}

#define METHOD_MSEARCH 1
#define METHOD_NOTIFY 2

/* ParseSSDPPacket() :
 * parse a received SSDP Packet and call
 * updateDevice() or removeDevice() as needed
 * return value :
 *    -1 : a device was removed
 *     0 : no device removed nor added
 *     1 : a device was added.  */
static int
ParseSSDPPacket(int s, const char * p, ssize_t n,
                const struct sockaddr * addr,
                const char * searched_device)
{
	const char * linestart;
	const char * lineend;
	const char * nameend;
	const char * valuestart;
	struct header headers[3];
	int i, r = 0;
	int methodlen;
	int nts = -1;
	int method = -1;
	unsigned int lifetime = 180;	/* 3 minutes by default */
	const char * st = NULL;
	int st_len = 0;

	/* first check from what subnet is the sender */
	/* don't care
	if(get_lan_for_peer(addr) == NULL) {
		char addr_str[64];
		sockaddr_to_string(addr, addr_str, sizeof(addr_str));
		warnx("peer %s is not from a LAN",
		       addr_str);
		return 0;
	}
	*/

	/* do the parsing */
	memset(headers, 0, sizeof(headers));
	for(methodlen = 0;
	    methodlen < n && (isalpha(p[methodlen]) || p[methodlen]=='-');
		methodlen++);
	if(methodlen==8 && 0==memcmp(p, "M-SEARCH", 8))
		method = METHOD_MSEARCH;
	else if(methodlen==6 && 0==memcmp(p, "NOTIFY", 6))
		method = METHOD_NOTIFY;
	else if(methodlen==4 && 0==memcmp(p, "HTTP", 4)) {
		/* answer to a M-SEARCH => process it as a NOTIFY
		 * with NTS: ssdp:alive */
		method = METHOD_NOTIFY;
		nts = NTS_SSDP_ALIVE;
	}
	linestart = p;
	while(linestart < p + n - 2) {
		/* start parsing the line : detect line end */
		lineend = linestart;
		while(lineend < p + n && *lineend != '\n' && *lineend != '\r')
			lineend++;
		/*printf("line: '%.*s'\n", lineend - linestart, linestart);*/
		/* detect name end : ':' character */
		nameend = linestart;
		while(nameend < lineend && *nameend != ':')
			nameend++;
		/* detect value */
		if(nameend < lineend)
			valuestart = nameend + 1;
		else
			valuestart = nameend;
		/* trim spaces */
		while(valuestart < lineend && isspace(*valuestart))
			valuestart++;
		/* suppress leading " if needed */
		if(valuestart < lineend && *valuestart=='\"')
			valuestart++;
		if(nameend > linestart && valuestart < lineend) {
			int l = nameend - linestart;	/* header name length */
			int m = lineend - valuestart;	/* header value length */
			/* suppress tailing spaces */
			while(m>0 && isspace(valuestart[m-1]))
				m--;
			/* suppress tailing ' if needed */
			if(m>0 && valuestart[m-1] == '\"')
				m--;
			i = -1;
			/*printf("--%.*s: (%d)%.*s--\n", l, linestart,
			                           m, m, valuestart);*/
			if(l==2 && 0==strncasecmp(linestart, "nt", 2))
				i = HEADER_NT;
			else if(l==3 && 0==strncasecmp(linestart, "usn", 3))
				i = HEADER_USN;
			else if(l==3 && 0==strncasecmp(linestart, "nts", 3)) {
				if(m==10 && 0==strncasecmp(valuestart, "ssdp:alive", 10))
					nts = NTS_SSDP_ALIVE;
				else if(m==11 && 0==strncasecmp(valuestart, "ssdp:byebye", 11))
					nts = NTS_SSDP_BYEBYE;
				else if(m==11 && 0==strncasecmp(valuestart, "ssdp:update", 11))
					nts = NTS_SSDP_UPDATE;
			}
			else if(l==8 && 0==strncasecmp(linestart, "location", 8))
				i = HEADER_LOCATION;
			else if(l==13 && 0==strncasecmp(linestart, "cache-control", 13)) {
				/* parse "name1=value1, name_alone, name2=value2" string */
				const char * name = valuestart;	/* name */
				const char * val;				/* value */
				int rem = m;	/* remaining bytes to process */
				while(rem > 0) {
					val = name;
					while(val < name + rem && *val != '=' && *val != ',')
						val++;
					if(val >= name + rem)
						break;
					if(*val == '=') {
						while(val < name + rem && (*val == '=' || isspace(*val)))
							val++;
						if(val >= name + rem)
							break;
						if(0==strncasecmp(name, "max-age", 7))
							lifetime = (unsigned int)strtoul(val, 0, 0);
						/* move to the next name=value pair */
						while(rem > 0 && *name != ',') {
							rem--;
							name++;
						}
						/* skip spaces */
						while(rem > 0 && (*name == ',' || isspace(*name))) {
							rem--;
							name++;
						}
					} else {
						rem -= (val - name);
						name = val;
						while(rem > 0 && (*name == ',' || isspace(*name))) {
							rem--;
							name++;
						}
					}
				}
				/*syslog(LOG_DEBUG, "**%.*s**%u", m, valuestart, lifetime);*/
			} else if(l==2 && 0==strncasecmp(linestart, "st", 2)) {
				st = valuestart;
				st_len = m;
				if(method == METHOD_NOTIFY)
					i = HEADER_NT;	/* it was a M-SEARCH response */
			}
			if(i>=0) {
				headers[i].p = valuestart;
				headers[i].l = m;
			}
		}
		linestart = lineend;
		while((*linestart == '\n' || *linestart == '\r') && linestart < p + n)
			linestart++;
	}
	warnx("SSDP request: '%.*s' (%d) %s %s=%.*s",
	       methodlen, p, method, nts_to_str(nts),
	       (method==METHOD_NOTIFY)?"nt":"st",
	       (method==METHOD_NOTIFY)?headers[HEADER_NT].l:st_len,
	       (method==METHOD_NOTIFY)?headers[HEADER_NT].p:st);
	switch(method) {
	case METHOD_NOTIFY:
		if(nts==NTS_SSDP_ALIVE || nts==NTS_SSDP_UPDATE) {
			if(headers[HEADER_NT].p && headers[HEADER_USN].p && headers[HEADER_LOCATION].p) {
				/* filter if needed */
				if(searched_device &&
				   0 != memcmp(headers[HEADER_NT].p, searched_device, headers[HEADER_NT].l))
					break;
				r = updateDevice(headers, time(NULL) + lifetime);
			} else {
				warnx("missing header nt=%p usn=%p location=%p",
				       headers[HEADER_NT].p, headers[HEADER_USN].p,
				       headers[HEADER_LOCATION].p);
			}
		} else if(nts==NTS_SSDP_BYEBYE) {
			if(headers[HEADER_NT].p && headers[HEADER_USN].p) {
				r = removeDevice(headers);
			} else {
				warnx("missing header nt=%p usn=%p",
				       headers[HEADER_NT].p, headers[HEADER_USN].p);
			}
		}
		break;
	case METHOD_MSEARCH:
		processMSEARCH(s, st, st_len, addr);
		break;
	default:
		{
			char addr_str[64];
			sockaddr_to_string(addr, addr_str, sizeof(addr_str));
			warnx("method %.*s, don't know what to do (from %s)",
			       methodlen, p, addr_str);
		}
	}
	return r;
}

/* main(): program entry point */
int main(int argc, char * * argv)
{
	char buf[1500];
	ssize_t n;
	int i;
	int deltadev = 0;
	struct sockaddr_in sendername = { AF_INET, CLPORTHEX, { CLADDRHEX } };
	socklen_t sendername_len;
	const char * searched_device = NULL;	/* if not NULL, search/filter a specific device type */

	LIST_INIT(&reqlisthead);
	LIST_INIT(&servicelisthead);
	LIST_INIT(&lan_addrs);

		{
			sendername_len = sizeof(struct sockaddr_in);

			/* read from stdin */
			n = read(0, buf, sizeof(buf));
			/* n = recvfrom(s_ssdp, buf, sizeof(buf), 0,
			             (struct sockaddr *)&sendername, &sendername_len); */
			if(n<0)
			{
				 /* EAGAIN, EWOULDBLOCK, EINTR : silently ignore (try again next time)
				  * other errors : log to LOG_ERR */
				if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
					warnx("recvfrom");
			}
			else
			{
				/* Parse and process the packet received */
				/*printf("%.*s", n, buf);*/
				i = ParseSSDPPacket(0, buf, n,
				                    (struct sockaddr *)&sendername, searched_device);
				warnx("** i=%d deltadev=%d **", i, deltadev);
				if(i==0 || (i*deltadev < 0))
				{
					if(deltadev > 0)
						warnx("%d new devices added", deltadev);
					else if(deltadev < 0)
						warnx("%d devices removed (good-bye!)", -deltadev);
					deltadev = i;
				}
				else if((i*deltadev) >= 0)
				{
					deltadev += i;
				}
			}
		}

	return 0;
}

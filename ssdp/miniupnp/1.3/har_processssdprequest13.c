/* test harness for ProcessSSDPRequest function, based on minissdp.c */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SSDP_PORT (1900)
#define SSDP_MCAST_ADDR ("239.255.255.250")
#define MAX_LAN_ADDR (4)
#define OS_VERSION "Linux/4.18.18-200.fc28.x86_64"
#define MINIUPNPD_SERVER_STRING OS_VERSION " UPnP/1.0 MiniUPnPd/1.3"
#define ROOTDESC_PATH "/rootDesc.xml"

/* dummy LAN address */
#define MYADDRSTR "192.168.1.100"
#define MYADDRHEX 0x0101a8c0 /* 192.168.1.1   */
#define MYMASKHEX 0x00ffffff /* 255.255.255.0 */

/* dummy client address */
#define CLADDRHEX 0x6401a8c0 /* 192.168.1.100 */
#define CLPORTHEX 0x3930     /* 12345 */

char uuidvalue[] = "uuid:00000000-0000-0000-0000-000000000000";
int n_lan_addr = 1;

struct lan_addr_s {
	char str[16];	/* example: 192.168.0.1 */
	struct in_addr addr, mask;	/* ip/mask */
};

struct lan_addr_s lan_addr[MAX_LAN_ADDR] = 
{ { MYADDRSTR, { MYADDRHEX }, { MYMASKHEX } } };

static const char * const known_service_types[] =
{
	"upnp:rootdevice",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:",
	"urn:schemas-upnp-org:device:WANConnectionDevice:",
	"urn:schemas-upnp-org:device:WANDevice:",
	"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:",
	"urn:schemas-upnp-org:service:WANIPConnection:",
	"urn:schemas-upnp-org:service:WANPPPConnection:",
	"urn:schemas-upnp-org:service:Layer3Forwarding:",
	0
};

static void
SendSSDPAnnounce2(int s, struct sockaddr_in sockname,
                  const char * st, int st_len, const char * suffix,
                  const char * host, unsigned short port)
{
	int l;
	char buf[512];
	l = snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n"
		"CACHE-CONTROL: max-age=120\r\n"
		/*"DATE: ...\r\n"*/
		"ST: %.*s%s\r\n"
		"USN: %s::%.*s%s\r\n"
		"EXT:\r\n"
		"SERVER: " MINIUPNPD_SERVER_STRING "\r\n"
		"LOCATION: http://%s:%u" ROOTDESC_PATH "\r\n"
		"\r\n",
		st_len, st, suffix,
		uuidvalue, st_len, st, suffix,
		host, (unsigned int)port);
	/* modified to use printf instead of sendto */
	printf("%s\n", buf);
}

void
ProcessSSDPRequest(int s, unsigned short port)
{
	int n;
	char bufr[1500];
	socklen_t len_r;
/*	struct sockaddr_in sendername;*/
	int i, l;
	int lan_addr_index = 0;
	char * st = 0;
	int st_len = 0;
	len_r = sizeof(struct sockaddr_in);

	/* dummy source address and port for the request */
	struct sockaddr_in sendername =
        	{ AF_INET, CLPORTHEX, { CLADDRHEX } };

        /* read data from stdin instead of from network */
        ssize_t res = read(0, bufr, sizeof(bufr));
        if (res < 0) { return; } else { n = res; }

	if(memcmp(bufr, "NOTIFY", 6) == 0)
	{
		/* ignore NOTIFY packets. */
		return;
	}
	else if(memcmp(bufr, "M-SEARCH", 8) == 0)
	{
		i = 0;
		while(i < n)
		{
			while(bufr[i] != '\r' || bufr[i+1] != '\n')
				i++;
			i += 2;
			if(strncasecmp(bufr+i, "st:", 3) == 0)
			{
				st = bufr+i+3;
				st_len = 0;
				while((*st == ' ' || *st == '\t') && (st < bufr + n))
					st++;
				while(st[st_len]!='\r' && st[st_len]!='\n'
				     && (st + st_len < bufr + n))
					st_len++;
			}
		}
		if(st)
		{
			/* replaced syslog with printf */
			printf("SSDP M-SEARCH from %s:%d ST: %.*s\n",
	        	   inet_ntoa(sendername.sin_addr),
	           	   ntohs(sendername.sin_port),
				   st_len, st);
			/* find in which sub network the client is */
			for(i = 0; i<n_lan_addr; i++)
			{
				if( (sendername.sin_addr.s_addr & lan_addr[i].mask.s_addr)
				   == (lan_addr[i].addr.s_addr & lan_addr[i].mask.s_addr))
				{
					lan_addr_index = i;
					break;
				}
			}
			/* Responds to request with a device as ST header */
			for(i = 0; known_service_types[i]; i++)
			{
				l = (int)strlen(known_service_types[i]);
				if(l<=st_len && (0 == memcmp(st, known_service_types[i], l)))
				{
					SendSSDPAnnounce2(s, sendername,
					                  st, st_len, "",
					                  lan_addr[lan_addr_index].str, port);
					break;
				}
			}
			/* Responds to request with ST: ssdp:all */
			if(st_len==8 && (0 == memcmp(st, "ssdp:all", 8)))
			{
				for(i=0; known_service_types[i]; i++)
				{
					l = (int)strlen(known_service_types[i]);
					SendSSDPAnnounce2(s, sendername,
					                  known_service_types[i], l, i==0?"":"1",
					                  lan_addr[lan_addr_index].str, port);
				}
			}
			/* responds to request by UUID value */
			l = (int)strlen(uuidvalue);
			if(l==st_len && (0 == memcmp(st, uuidvalue, l)))
			{
				SendSSDPAnnounce2(s, sendername, st, st_len, "",
				                  lan_addr[lan_addr_index].str, port);
			}
		}
		else
		{
			/* replaced syslog with printf */
			printf("Invalid SSDP M-SEARCH from %s:%d\n",
	        	   inet_ntoa(sendername.sin_addr), ntohs(sendername.sin_port));
		}
	}
	else
	{
		/* replaced syslog with printf */
		printf("Unknown udp packet received from %s:%d",
		       inet_ntoa(sendername.sin_addr), ntohs(sendername.sin_port));
	}
}

int main() {
    /* use dummy socket and port as arguments */
    ProcessSSDPRequest(1, 4321);
    return 0;
}

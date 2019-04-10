#include "upnp.h"
#include <stdio.h>
#include <stdlib.h>
#if UPNP_HAVE_TOOLS
#	include "upnptools.h"
#endif
/*#include "upnpdebug.h"*/

#define DESC_URL_SIZE 200

void readFromSSDPSocket(SOCKET socket);

/* dummy callback function */
int TvDeviceCallbackEventHandler(Upnp_EventType EventType, void *Event, void *Cookie)
{
        switch (EventType) {
        case UPNP_EVENT_SUBSCRIPTION_REQUEST:
        case UPNP_CONTROL_GET_VAR_REQUEST:
        case UPNP_CONTROL_ACTION_REQUEST:
        case UPNP_DISCOVERY_ADVERTISEMENT_ALIVE:
        case UPNP_DISCOVERY_SEARCH_RESULT:
        case UPNP_DISCOVERY_SEARCH_TIMEOUT:
        case UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE:
        case UPNP_CONTROL_ACTION_COMPLETE:
        case UPNP_CONTROL_GET_VAR_COMPLETE:
        case UPNP_EVENT_RECEIVED:
        case UPNP_EVENT_RENEWAL_COMPLETE:
        case UPNP_EVENT_SUBSCRIBE_COMPLETE:
        case UPNP_EVENT_UNSUBSCRIBE_COMPLETE:
                break;
        default:
                printf
                    ("Error in TvDeviceCallbackEventHandler: unknown event type %d\n",
                     EventType);
        }
        return 0;
}

int
main (int argc, char* argv[])
{
	/*
	int rc;
	int a, b, c;
	*/

	/*
	 * Check library version (and formats)
	 */
/*	printf ("\n");
	
	printf ("UPNP_VERSION_STRING = \"%s\"\n", UPNP_VERSION_STRING);
	printf ("UPNP_VERSION_MAJOR  = %d\n",	  UPNP_VERSION_MAJOR);
	printf ("UPNP_VERSION_MINOR  = %d\n",	  UPNP_VERSION_MINOR);
	printf ("UPNP_VERSION_PATCH  = %d\n",	  UPNP_VERSION_PATCH);
	printf ("UPNP_VERSION        = %d\n",	  UPNP_VERSION);
	
	if ( sscanf (UPNP_VERSION_STRING, "%d.%d.%d", &a, &b, &c) != 3 ||
	     a != UPNP_VERSION_MAJOR ||
	     b != UPNP_VERSION_MINOR ||
	     c != UPNP_VERSION_PATCH ) {
		printf ("** ERROR malformed UPNP_VERSION_STRING\n");
		exit (EXIT_FAILURE);
	}
*/
	
	/*
	 * Check library optional features
	 */
/*
	printf ("\n");
	
#if UPNP_HAVE_DEBUG
	printf ("UPNP_HAVE_DEBUG \t= yes\n");
#else
	printf ("UPNP_HAVE_DEBUG \t= no\n");
#endif
	
#if UPNP_HAVE_CLIENT
	printf ("UPNP_HAVE_CLIENT\t= yes\n");
#else
	printf ("UPNP_HAVE_CLIENT\t= no\n");
#endif
	
#if UPNP_HAVE_DEVICE
	printf ("UPNP_HAVE_DEVICE\t= yes\n");
#else
	printf ("UPNP_HAVE_DEVICE\t= no\n");
#endif
	
#if UPNP_HAVE_WEBSERVER
	printf ("UPNP_HAVE_WEBSERVER\t= yes\n");
#else
	printf ("UPNP_HAVE_WEBSERVER\t= no\n");
#endif

#if UPNP_HAVE_TOOLS
	printf ("UPNP_HAVE_TOOLS \t= yes\n");
#else
	printf ("UPNP_HAVE_TOOLS \t= no\n");
#endif
*/
	
	UpnpDevice_Handle h = -1;
	int ret = UPNP_E_SUCCESS;
	char desc_doc_url[DESC_URL_SIZE];
	snprintf(desc_doc_url, DESC_URL_SIZE, "http://192.168.1.123:12345/tvdevicedesc.xml");

        ret = UpnpRegisterRootDevice(desc_doc_url, TvDeviceCallbackEventHandler,
                                     &h, &h);
        if (ret != UPNP_E_SUCCESS) {
                printf("Error registering the rootdevice : %d\n",
                                 ret);
	}
#ifdef __AFL_HAVE_MANUAL_CONTROL
	while (__AFL_LOOP(1000)) {
#endif
		readFromSSDPSocket(1);
#ifdef __AFL_HAVE_MANUAL_CONTROL
	}
#endif
	
	exit (EXIT_SUCCESS);
}

/* test harness for SOAP fuzzing of libupnp 1.8.4 */

#include "upnp.h"
#include <stdio.h>
#include <stdlib.h>
#if UPNP_HAVE_TOOLS
#	include "upnptools.h"
#endif
#include "httpparser.h"
#include "httpreadwrite.h"
/*#include "miniserver.h"*/
#include "soaplib.h"
/*#include "upnpdebug.h"*/
#include "sample_util.h"

#define DESC_URL_SIZE 200

int TvDeviceCallbackEventHandler(Upnp_EventType, const void *Event, void *Cookie);

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

	http_parser_t parser;
	http_parser_t * hparser = &parser;
	http_message_t *hmsg = &parser.msg;
	int http_error_code = 0;
	int ret_code;
	int timeout = 0;
	
	UpnpDevice_Handle h = -1;
	int ret = UPNP_E_SUCCESS;
	char desc_doc_url[DESC_URL_SIZE];
	snprintf(desc_doc_url, DESC_URL_SIZE, "http://192.168.1.123:12345/tvdevicedesc.xml");

        ret = UpnpRegisterRootDevice(desc_doc_url, TvDeviceCallbackEventHandler,
                                     &h, &h);
        if (ret != UPNP_E_SUCCESS) {
                printf("Error registering the rootdevice : %d\n",
                                 ret);
	} /*else {
	}*/

	SampleUtil_Initialize(linux_print);
	readxmlfile();

#ifdef __AFL_HAVE_MANUAL_CONTROL
	while (__AFL_LOOP(1000)) {
#endif

		TvDeviceStateTableInit(desc_doc_url);
		http_error_code = 0;
		ret_code = http_RecvMessage(0, &parser, HTTPMETHOD_UNKNOWN, &timeout, &http_error_code);
		if (ret_code != 0) {
			goto error_handler;
	        }
		/* dispatch */
/*		http_error_code = dispatch_request(&info, &parser);*/

		soap_device_callback(hparser, &hparser->msg, 0);

	error_handler:
		if (http_error_code > 0) {
			http_SendStatusResponse(0, http_error_code, 1, 1);
		}
		httpmsg_destroy(hmsg);

#ifdef __AFL_HAVE_MANUAL_CONTROL
	}
#endif
	
	exit (EXIT_SUCCESS);
}

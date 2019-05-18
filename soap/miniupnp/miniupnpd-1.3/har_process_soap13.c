/* test harness for Process_upnphttp function for miniupnp 1.3 */

#include <stdio.h>
#include "upnphttp.h"

int main() {
    struct upnphttp * h = NULL;
    h = New_upnphttp(0);
    if (h == NULL) {
	    printf("Allocation error\n");
	    return -1;
    }
    h->state = 0;
    Process_upnphttp(h);
    Delete_upnphttp(h);
    return 0;
}

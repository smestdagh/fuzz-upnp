## Build

- Library: apply libupnp-1.8.4-soap.diff and build
- Apply tv_device.diff to tv_device.c to obtain modified tvdev.c
- Sources:
     har_libupnp_soap.c
     tvdev.c
     sample_util.c
- Link with:
    - Libupnp: libupnp, libixml
    - System: libc, libpthread


#ifndef __6LOWPAN_NHC_ROUTE_H
#define __6LOWPAN_NHC_ROUTE_H

#define LOWPAN_NHC_ROUTE_LEN	1
#define LOWPAN_NHC_ROUTE_ID_0	0xe2
#define LOWPAN_NHC_ROUTE_MASK_0	0xfe

int lowpan_init_nhc_route(void);
void lowpan_cleanup_nhc_route(void);

#endif /* __6LOWPAN_NHC_ROUTE_H */

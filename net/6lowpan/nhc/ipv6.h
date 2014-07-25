#ifndef __6LOWPAN_NHC_IPV6_H
#define __6LOWPAN_NHC_IPV6_H

#define LOWPAN_NHC_IPV6_LEN	1
#define LOWPAN_NHC_IPV6_ID_0	0xee
#define LOWPAN_NHC_IPV6_MASK_0	0xfe

int lowpan_init_nhc_ipv6(void);
void lowpan_cleanup_nhc_ipv6(void);

#endif /* __6LOWPAN_NHC_IPV6_H */

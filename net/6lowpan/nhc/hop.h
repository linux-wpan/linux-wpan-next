#ifndef __6LOWPAN_NHC_HOP_H
#define __6LOWPAN_NHC_HOP_H

#define LOWPAN_NHC_HOP_LEN	1
#define LOWPAN_NHC_HOP_ID_0	0xe0
#define LOWPAN_NHC_HOP_MASK_0	0xfe

int lowpan_init_nhc_hop(void);
void lowpan_cleanup_nhc_hop(void);

#endif /* __6LOWPAN_NHC_HOP_H */

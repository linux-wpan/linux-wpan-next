#ifndef __6LOWPAN_NHC_FRAG_H
#define __6LOWPAN_NHC_FRAG_H

#define LOWPAN_NHC_FRAG_LEN	1
#define LOWPAN_NHC_FRAG_ID_0	0xe4
#define LOWPAN_NHC_FRAG_MASK_0	0xfe

int lowpan_init_nhc_frag(void);
void lowpan_cleanup_nhc_frag(void);

#endif /* __6LOWPAN_NHC_FRAG_H */

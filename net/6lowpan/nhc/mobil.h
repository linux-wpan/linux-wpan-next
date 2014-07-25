#ifndef __6LOWPAN_NHC_MOBIL_H
#define __6LOWPAN_NHC_MOBIL_H

#define LOWPAN_NHC_MOBIL_LEN	1
#define LOWPAN_NHC_MOBIL_ID_0	0xe8
#define LOWPAN_NHC_MOBIL_MASK_0	0xfe

int lowpan_init_nhc_mobil(void);
void lowpan_cleanup_nhc_mobil(void);

#endif /* __6LOWPAN_NHC_MOBIL_H */

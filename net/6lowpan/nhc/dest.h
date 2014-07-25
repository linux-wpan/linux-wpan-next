#ifndef __6LOWPAN_NHC_DEST_H
#define __6LOWPAN_NHC_DEST_H

#define LOWPAN_NHC_DEST_LEN	1
#define LOWPAN_NHC_DEST_ID_0	0xe6
#define LOWPAN_NHC_DEST_MASK_0	0xfe

int lowpan_init_nhc_dest(void);
void lowpan_cleanup_nhc_dest(void);

#endif /* __6LOWPAN_NHC_DEST_H */

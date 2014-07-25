/*	6LoWPAN IPv6 Fragment Header compression
 *
 *
 *	Authors:
 *	Alexander Aring		<aar@pengutronix.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <net/6lowpan.h>
#include <linux/skbuff.h>

#include "core.h"
#include "frag.h"

static int frag_uncompress(struct sk_buff **skb)
{
	return -ENOTSUPP;
}

static int frag_compress(struct sk_buff *skb, u8 **hc_ptr)
{
	return -ENOTSUPP;
}

static void frag_nhid_setup(struct lowpan_nhc *nhc)
{
	nhc->id[0] = LOWPAN_NHC_FRAG_ID_0;
	nhc->idmask[0] = LOWPAN_NHC_FRAG_MASK_0;
}

LOWPAN_NHC(frag_nhc, "IPv6 Fragment Header", NEXTHDR_FRAGMENT,
	   frag_nhid_setup, LOWPAN_NHC_FRAG_LEN, frag_uncompress,
	   frag_compress);

int lowpan_init_nhc_frag(void)
{
	return lowpan_add_nhc(&frag_nhc);
}
EXPORT_SYMBOL(lowpan_init_nhc_frag);

void lowpan_cleanup_nhc_frag(void)
{
	lowpan_del_nhc(&frag_nhc);
}
EXPORT_SYMBOL(lowpan_cleanup_nhc_frag);

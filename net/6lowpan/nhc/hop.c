/*	6LoWPAN IPv6 Hop-by-Hop Options Header compression
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
#include "hop.h"

static int hop_uncompress(struct sk_buff **skb)
{
	return -ENOTSUPP;
}

static int hop_compress(struct sk_buff *skb, u8 **hc_ptr)
{
	return -ENOTSUPP;
}

static void hop_nhid_setup(struct lowpan_nhc *nhc)
{
	nhc->id[0] = LOWPAN_NHC_HOP_ID_0;
	nhc->idmask[0] = LOWPAN_NHC_HOP_MASK_0;
}

LOWPAN_NHC(hop_nhc, "IPv6 Hop-by-Hop Options Header", NEXTHDR_HOP,
	   hop_nhid_setup, LOWPAN_NHC_HOP_LEN, hop_uncompress, hop_compress);

int lowpan_init_nhc_hop(void)
{
	return lowpan_add_nhc(&hop_nhc);
}
EXPORT_SYMBOL(lowpan_init_nhc_hop);

void lowpan_cleanup_nhc_hop(void)
{
	lowpan_del_nhc(&hop_nhc);
}
EXPORT_SYMBOL(lowpan_cleanup_nhc_hop);

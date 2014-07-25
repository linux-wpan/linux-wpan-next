/*	6LoWPAN IPv6 Destination Options Header compression
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
#include "dest.h"

static int dest_uncompress(struct sk_buff **skb)
{
	return -ENOTSUPP;
}

static int dest_compress(struct sk_buff *skb, u8 **hc_ptr)
{
	return -ENOTSUPP;
}

static void dest_nhid_setup(struct lowpan_nhc *nhc)
{
	nhc->id[0] = LOWPAN_NHC_DEST_ID_0;
	nhc->idmask[0] = LOWPAN_NHC_DEST_MASK_0;
}

LOWPAN_NHC(dest_nhc, "IPv6 Destination Options Header", NEXTHDR_DEST,
	   dest_nhid_setup, LOWPAN_NHC_DEST_LEN, dest_uncompress,
	   dest_compress);

int lowpan_init_nhc_dest(void)
{
	return lowpan_add_nhc(&dest_nhc);
}
EXPORT_SYMBOL(lowpan_init_nhc_dest);

void lowpan_cleanup_nhc_dest(void)
{
	lowpan_del_nhc(&dest_nhc);
}
EXPORT_SYMBOL(lowpan_cleanup_nhc_dest);

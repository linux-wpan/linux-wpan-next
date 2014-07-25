/*	6LoWPAN IPv6 Mobility Header compression
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
#include "mobil.h"

static int mobil_uncompress(struct sk_buff **skb)
{
	return -ENOTSUPP;
}

static int mobil_compress(struct sk_buff *skb, u8 **hc_ptr)
{
	return -ENOTSUPP;
}

static void mobil_nhid_setup(struct lowpan_nhc *nhc)
{
	nhc->id[0] = LOWPAN_NHC_MOBIL_ID_0;
	nhc->idmask[0] = LOWPAN_NHC_MOBIL_MASK_0;
}

LOWPAN_NHC(mobil_nhc, "IPv6 Mobility Header", NEXTHDR_MOBILITY,
	   mobil_nhid_setup, LOWPAN_NHC_MOBIL_LEN, mobil_uncompress,
	   mobil_compress);

int lowpan_init_nhc_mobil(void)
{
	return lowpan_add_nhc(&mobil_nhc);
}
EXPORT_SYMBOL(lowpan_init_nhc_mobil);

void lowpan_cleanup_nhc_mobil(void)
{
	lowpan_del_nhc(&mobil_nhc);
}
EXPORT_SYMBOL(lowpan_cleanup_nhc_mobil);

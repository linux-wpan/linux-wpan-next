/*	6LoWPAN IPv6 Routing Header compression
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
#include "route.h"

static int route_uncompress(struct sk_buff **skb)
{
	return -ENOTSUPP;
}

static int route_compress(struct sk_buff *skb, u8 **hc_ptr)
{
	return -ENOTSUPP;
}

static void route_nhid_setup(struct lowpan_nhc *nhc)
{
	nhc->id[0] = LOWPAN_NHC_ROUTE_ID_0;
	nhc->idmask[0] = LOWPAN_NHC_ROUTE_MASK_0;
}

LOWPAN_NHC(route_nhc, "IPv6 Routing Header", NEXTHDR_ROUTING, route_nhid_setup,
	   LOWPAN_NHC_ROUTE_LEN, route_uncompress, route_compress);

int lowpan_init_nhc_route(void)
{
	return lowpan_add_nhc(&route_nhc);
}
EXPORT_SYMBOL(lowpan_init_nhc_route);

void lowpan_cleanup_nhc_route(void)
{
	lowpan_del_nhc(&route_nhc);
}
EXPORT_SYMBOL(lowpan_cleanup_nhc_route);

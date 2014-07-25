/*	6LoWPAN IPv6 Header compression
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
#include "ipv6.h"

static int ipv6_uncompress(struct sk_buff **skb)
{
	return -ENOTSUPP;
}

static int ipv6_compress(struct sk_buff *skb, u8 **hc_ptr)
{
	return -ENOTSUPP;
}

static void ipv6_nhid_setup(struct lowpan_nhc *nhc)
{
	nhc->id[0] = LOWPAN_NHC_IPV6_ID_0;
	nhc->idmask[0] = LOWPAN_NHC_IPV6_MASK_0;
}

LOWPAN_NHC(ipv6_nhc, "IPv6 Header", NEXTHDR_IPV6, ipv6_nhid_setup,
	   LOWPAN_NHC_IPV6_LEN, ipv6_uncompress, ipv6_compress);

int lowpan_init_nhc_ipv6(void)
{
	return lowpan_add_nhc(&ipv6_nhc);
}
EXPORT_SYMBOL(lowpan_init_nhc_ipv6);

void lowpan_cleanup_nhc_ipv6(void)
{
	lowpan_del_nhc(&ipv6_nhc);
}
EXPORT_SYMBOL(lowpan_cleanup_nhc_ipv6);

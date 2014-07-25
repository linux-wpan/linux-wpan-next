/*	6LoWPAN IPv6 UDP compression
 *
 *
 *	Authors:
 *	Alexander Aring		<aar@pengutronix.de>
 *
 *	Orignal written by:
 *	Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 *	Jon Smirl <jonsmirl@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <net/6lowpan.h>
#include <linux/skbuff.h>

#include "core.h"
#include "udp.h"

static int udp_uncompress(struct sk_buff **skb)
{
	struct udphdr uh;
	struct sk_buff *new;
	bool fail;
	u8 tmp = 0, val = 0;

	fail = lowpan_fetch_skb(*skb, &tmp, sizeof(tmp));

	pr_debug("UDP header uncompression\n");
	switch (tmp & LOWPAN_NHC_UDP_CS_P_11) {
	case LOWPAN_NHC_UDP_CS_P_00:
		fail |= lowpan_fetch_skb(*skb, &uh.source, sizeof(uh.source));
		fail |= lowpan_fetch_skb(*skb, &uh.dest, sizeof(uh.dest));
		break;
	case LOWPAN_NHC_UDP_CS_P_01:
		fail |= lowpan_fetch_skb(*skb, &uh.source, sizeof(uh.source));
		fail |= lowpan_fetch_skb(*skb, &val, sizeof(val));
		uh.dest = htons(val + LOWPAN_NHC_UDP_8BIT_PORT);
		break;
	case LOWPAN_NHC_UDP_CS_P_10:
		fail |= lowpan_fetch_skb(*skb, &val, sizeof(val));
		uh.source = htons(val + LOWPAN_NHC_UDP_8BIT_PORT);
		fail |= lowpan_fetch_skb(*skb, &uh.dest, sizeof(uh.dest));
		break;
	case LOWPAN_NHC_UDP_CS_P_11:
		fail |= lowpan_fetch_skb(*skb, &val, sizeof(val));
		uh.source = htons(LOWPAN_NHC_UDP_4BIT_PORT + (val >> 4));
		uh.dest = htons(LOWPAN_NHC_UDP_4BIT_PORT + (val & 0x0f));
		break;
	default:
		pr_debug("ERROR: unknown UDP format\n");
		return -EINVAL;
	}

	pr_debug("uncompressed UDP ports: src = %d, dst = %d\n",
		 ntohs(uh.source), ntohs(uh.dest));

	/* checksum */
	if (tmp & LOWPAN_NHC_UDP_CS_C) {
		pr_debug_ratelimited("checksum elided currently not supported\n");
		fail = true;
	} else {
		fail |= lowpan_fetch_skb(*skb, &uh.check, sizeof(uh.check));
	}

	if (fail)
		return -EINVAL;

	/* UDP lenght needs to be infered from the lower layers
	 * here, we obtain the hint from the remaining size of the
	 * frame
	 */
	uh.len = htons((*skb)->len + sizeof(struct udphdr));
	pr_debug("uncompressed UDP length: src = %d", ntohs(uh.len));

	/* replace the compressed UDP head by the uncompressed UDP
	 * header
	 */
	new = skb_copy_expand(*skb, sizeof(struct udphdr),
			      skb_tailroom(*skb), GFP_ATOMIC);
	kfree_skb(*skb);
	if (!new)
		return -ENOMEM;
	*skb = new;

	skb_push(*skb, sizeof(uh));
	skb_copy_to_linear_data(*skb, &uh, sizeof(struct udphdr));

	return 0;
}

static int udp_compress(struct sk_buff *skb, u8 **hc_ptr)
{
	struct udphdr *uh = udp_hdr(skb);
	u8 tmp;

	if (((ntohs(uh->source) & LOWPAN_NHC_UDP_4BIT_MASK) ==
	     LOWPAN_NHC_UDP_4BIT_PORT) &&
	    ((ntohs(uh->dest) & LOWPAN_NHC_UDP_4BIT_MASK) ==
	     LOWPAN_NHC_UDP_4BIT_PORT)) {
		pr_debug("UDP header: both ports compression to 4 bits\n");
		/* compression value */
		tmp = LOWPAN_NHC_UDP_CS_P_11;
		lowpan_push_hc_data(hc_ptr, &tmp, sizeof(tmp));
		/* source and destination port */
		tmp = ntohs(uh->dest) - LOWPAN_NHC_UDP_4BIT_PORT +
		      ((ntohs(uh->source) - LOWPAN_NHC_UDP_4BIT_PORT) << 4);
		lowpan_push_hc_data(hc_ptr, &tmp, sizeof(tmp));
	} else if ((ntohs(uh->dest) & LOWPAN_NHC_UDP_8BIT_MASK) ==
		   LOWPAN_NHC_UDP_8BIT_PORT) {
		pr_debug("UDP header: remove 8 bits of dest\n");
		/* compression value */
		tmp = LOWPAN_NHC_UDP_CS_P_01;
		lowpan_push_hc_data(hc_ptr, &tmp, sizeof(tmp));
		/* source port */
		lowpan_push_hc_data(hc_ptr, &uh->source, sizeof(uh->source));
		/* destination port */
		tmp = ntohs(uh->dest) - LOWPAN_NHC_UDP_8BIT_PORT;
		lowpan_push_hc_data(hc_ptr, &tmp, sizeof(tmp));
	} else if ((ntohs(uh->source) & LOWPAN_NHC_UDP_8BIT_MASK) ==
		   LOWPAN_NHC_UDP_8BIT_PORT) {
		pr_debug("UDP header: remove 8 bits of source\n");
		/* compression value */
		tmp = LOWPAN_NHC_UDP_CS_P_10;
		lowpan_push_hc_data(hc_ptr, &tmp, sizeof(tmp));
		/* source port */
		tmp = ntohs(uh->source) - LOWPAN_NHC_UDP_8BIT_PORT;
		lowpan_push_hc_data(hc_ptr, &tmp, sizeof(tmp));
		/* destination port */
		lowpan_push_hc_data(hc_ptr, &uh->dest, sizeof(uh->dest));
	} else {
		pr_debug("UDP header: can't compress\n");
		/* compression value */
		tmp = LOWPAN_NHC_UDP_CS_P_00;
		lowpan_push_hc_data(hc_ptr, &tmp, sizeof(tmp));
		/* source port */
		lowpan_push_hc_data(hc_ptr, &uh->source, sizeof(uh->source));
		/* destination port */
		lowpan_push_hc_data(hc_ptr, &uh->dest, sizeof(uh->dest));
	}

	/* checksum is always inline */
	lowpan_push_hc_data(hc_ptr, &uh->check, sizeof(uh->check));

	/* skip the UDP header */
	skb_pull(skb, sizeof(struct udphdr));

	return 0;
}

static void udp_nhid_setup(struct lowpan_nhc *nhc)
{
	nhc->id[0] = LOWPAN_NHC_UDP_ID;
	nhc->idmask[0] = LOWPAN_NHC_UDP_MASK;
}

LOWPAN_NHC(udp_nhc, "IPv6 UDP Header", NEXTHDR_UDP,  udp_nhid_setup,
	   LOWPAN_NHC_UDP_LEN, udp_uncompress, udp_compress);

int lowpan_init_nhc_udp(void)
{
	return lowpan_add_nhc(&udp_nhc);
}
EXPORT_SYMBOL(lowpan_init_nhc_udp);

void lowpan_cleanup_nhc_udp(void)
{
	lowpan_del_nhc(&udp_nhc);
}
EXPORT_SYMBOL(lowpan_cleanup_nhc_udp);

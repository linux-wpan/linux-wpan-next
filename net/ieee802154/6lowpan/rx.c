/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Authors:
 * Alexander Aring <aar@pengutronix.de>
 *
 * Original Authors:
 * Copyright (c) 2011 Jon Smirl <jonsmirl@gmail.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <net/cfg802154.h>
#include <net/af_ieee802154.h>
#include <net/ieee802154_netdev.h>
#include <net/6lowpan.h>

#include "6lowpan_i.h"
#include "reassembly.h"

static int lowpan_give_skb_to_devices(struct sk_buff *skb,
				      struct net_device *wdev)
{
	struct net_device *ldev = wdev->ieee802154_ptr->lowpan_dev;
	struct sk_buff *skb_cp;

	skb_cp = skb_copy(skb, GFP_ATOMIC);
	if (!skb_cp)
		return NET_RX_DROP;

	skb_cp->dev = ldev;

	return netif_rx(skb_cp);
}

static int process_data(struct sk_buff *skb, const struct ieee802154_hdr *hdr)
{
	u8 iphc0, iphc1;
	struct ieee802154_addr_sa sa, da;
	void *sap, *dap;

	raw_dump_table(__func__, "raw skb data dump", skb->data, skb->len);
	/* at least two bytes will be used for the encoding */
	if (skb->len < 2)
		goto drop;

	if (lowpan_fetch_skb_u8(skb, &iphc0))
		goto drop;

	if (lowpan_fetch_skb_u8(skb, &iphc1))
		goto drop;

	ieee802154_addr_to_sa(&sa, &hdr->source);
	ieee802154_addr_to_sa(&da, &hdr->dest);

	if (sa.addr_type == IEEE802154_ADDR_SHORT)
		sap = &sa.short_addr;
	else
		sap = &sa.hwaddr;

	if (da.addr_type == IEEE802154_ADDR_SHORT)
		dap = &da.short_addr;
	else
		dap = &da.hwaddr;

	return lowpan_process_data(skb, skb->dev, sap, sa.addr_type,
				   IEEE802154_ADDR_LEN, dap, da.addr_type,
				   IEEE802154_ADDR_LEN, iphc0, iphc1,
				   lowpan_give_skb_to_devices);

drop:
	kfree_skb(skb);
	return -EINVAL;
}

static int lowpan_rcv(struct sk_buff *skb, struct net_device *wdev,
		      struct packet_type *pt, struct net_device *orig_wdev)
{
	struct net_device *ldev = wdev->ieee802154_ptr->lowpan_dev;
	struct ieee802154_hdr hdr;
	int ret;
	int hlen;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto drop;

	/* TODO checking on !ldev needs locking? maybe we can stop rx queue */
	if (!ldev && !netif_running(ldev) && !netif_running(wdev))
		goto drop_skb;

	if (wdev->type != ARPHRD_IEEE802154)
		goto drop_skb;

	hlen = ieee802154_hdr_peek_addrs(skb, &hdr);

	/* check that it's our buffer */
	if (skb->data[0] == LOWPAN_DISPATCH_IPV6) {
		skb->protocol = htons(ETH_P_IPV6);
		skb->pkt_type = PACKET_HOST;

		/* Pull off the 1-byte of 6lowpan header. */
		skb_pull(skb, 1);

		ret = lowpan_give_skb_to_devices(skb, NULL);
		if (ret == NET_RX_DROP)
			goto drop;
	} else {
		switch (skb->data[0] & 0xe0) {
		case LOWPAN_DISPATCH_IPHC:	/* ipv6 datagram */
			ret = process_data(skb, &hdr);
			if (ret == NET_RX_DROP)
				goto drop;
			break;
		case LOWPAN_DISPATCH_FRAG1:	/* first fragment header */
			ret = lowpan_frag_rcv(skb, LOWPAN_DISPATCH_FRAG1);
			if (ret == 1) {
				ret = process_data(skb, &hdr);
				if (ret == NET_RX_DROP)
					goto drop;
			}
			break;
		case LOWPAN_DISPATCH_FRAGN:	/* next fragments headers */
			ret = lowpan_frag_rcv(skb, LOWPAN_DISPATCH_FRAGN);
			if (ret == 1) {
				ret = process_data(skb, &hdr);
				if (ret == NET_RX_DROP)
					goto drop;
			}
			break;
		default:
			break;
		}
	}

	return NET_RX_SUCCESS;
drop_skb:
	kfree_skb(skb);
drop:
	return NET_RX_DROP;
}

static struct packet_type lowpan_packet_type = {
	.type = htons(ETH_P_IEEE802154),
	.func = lowpan_rcv,
};

void lowpan_init_rx(void)
{
	dev_add_pack(&lowpan_packet_type);
}

void lowpan_cleanup_rx(void)
{
	dev_remove_pack(&lowpan_packet_type);
}

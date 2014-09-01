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
#include <net/ieee802154.h>
#include <net/ieee802154_netdev.h>
#include <net/6lowpan.h>

#include "6lowpan_i.h"
#include "reassembly.h"

static void
lowpan_rx_handlers_result(struct sk_buff *skb, lowpan_rx_result res)
{
	switch (res) {
	case RX_DROP_UNUSABLE:
		kfree_skb(skb);
		break;
	}
}

static int lowpan_give_skb_to_devices(struct sk_buff *skb,
				      struct net_device *ldev)
{
	ldev->stats.rx_packets++;
	ldev->stats.rx_bytes += skb->len;

	netif_receive_skb(skb);

	return 0;
}

static void lowpan_rx_handlers(struct sk_buff *skb, struct lowpan_addr_info *info);

static int lowpan_rx_h_frag(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	int ret;

	if (((skb->data[0] & 0xe0) != LOWPAN_DISPATCH_FRAG1) &&
	    ((skb->data[0] & 0xe0) != LOWPAN_DISPATCH_FRAGN))
		return RX_CONTINUE;

	ret = lowpan_frag_rcv(skb, skb->data[0] & 0xe0, info);
	if (ret == 1)
		lowpan_rx_handlers(skb, info);

	return RX_QUEUED;
}

static int lowpan_rx_h_iphc(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	u8 iphc0, iphc1, daddr_mode, saddr_mode;
	void *daddr, *saddr;
	int ret;

	if ((skb->data[0] & 0xe0) != LOWPAN_DISPATCH_IPHC)
		return RX_CONTINUE;

	raw_dump_table(__func__, "raw skb data dump", skb->data, skb->len);

	if (lowpan_fetch_skb_u8(skb, &iphc0))
		goto drop;

	if (lowpan_fetch_skb_u8(skb, &iphc1))
		goto drop;

	/* TODO remove this handling do __le16 handling in lowpan_process_data */
	/* TODO we shouldn't convert mac values to cpu understandable things */
	switch (info->daddr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		daddr_mode = IEEE802154_ADDR_LONG;
		daddr = &info->daddr.u.extended;
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		daddr_mode = IEEE802154_ADDR_SHORT;
		daddr = &info->daddr.u.short_;
		break;
	default:
		/* dataframes should contain real addresses */
		BUG();
	}

	/* TODO remove this handling do __le16 handling in lowpan_process_data */
	/* TODO we shouldn't convert mac values to cpu understandable things */
	switch (info->saddr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		saddr_mode = IEEE802154_ADDR_LONG;
		saddr = &info->saddr.u.extended;
		break;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		saddr_mode = IEEE802154_ADDR_SHORT;
		saddr = &info->saddr.u.short_;
		break;
	default:
		/* dataframes should contain real addresses */
		BUG();
	}


	ret = lowpan_process_data(skb, skb->dev, saddr, saddr_mode,
				  IEEE802154_ADDR_LEN, daddr, daddr_mode,
				  IEEE802154_ADDR_LEN, iphc0, iphc1,
				  lowpan_give_skb_to_devices);

	if (ret < 0)
		return RX_DROP_UNUSABLE;

	return RX_QUEUED;
drop:
	return RX_DROP_UNUSABLE;
}

static int lowpan_rx_h_ipv6(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	int ret;

	if (skb->data[0] != LOWPAN_DISPATCH_IPV6)
		return RX_CONTINUE;

	skb->protocol = htons(ETH_P_IPV6);

	/* Pull off the 1-byte of 6lowpan header. */
	skb_pull(skb, 1);

	ret = lowpan_give_skb_to_devices(skb, NULL);
	if (ret < 0)
		return RX_DROP_UNUSABLE;

	return RX_QUEUED;
}

static void
lowpan_rx_handlers(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	int ret;

#define CALL_RXH(rxh)			\
	do {				\
		ret = rxh(skb, info);	\
		if (ret != RX_CONTINUE)	\
			goto rxh_next;	\
	} while (0);

	/* likely at first */
	CALL_RXH(lowpan_rx_h_frag);
	CALL_RXH(lowpan_rx_h_iphc);
	CALL_RXH(lowpan_rx_h_ipv6);

rxh_next:
	lowpan_rx_handlers_result(skb, ret);
#undef CALL_RXH
}

static inline void
lowpan_get_addr_info_from_hdr(struct ieee802154_hdr_foo *hdr,
			      struct lowpan_addr_info *info)
{
	struct ieee802154_addr_foo daddr, saddr;

	daddr = ieee802154_hdr_daddr(hdr);
	info->daddr.mode = daddr.mode;
	switch (info->daddr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		info->daddr.u.extended = swab64(daddr.u.extended);
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		info->daddr.u.short_ = swab16(daddr.u.short_);
		break;
	default:
		BUG();
	}

	saddr = ieee802154_hdr_saddr(hdr);
	info->saddr.mode = saddr.mode;
	switch (info->saddr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		info->saddr.u.extended = swab64(saddr.u.extended);
		break;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		info->saddr.u.short_ = swab16(saddr.u.short_);
		break;
	default:
		BUG();
	}
}

static lowpan_rx_result lowpan_rx_h_check(struct sk_buff *skb,
					  struct lowpan_addr_info *info)
{
	struct ieee802154_hdr_foo *hdr;
	__le16 fc;

	if (skb->len < 2)
		return RX_DROP_UNUSABLE;

	hdr = (struct ieee802154_hdr_foo *)skb_mac_header(skb);
	fc = hdr->frame_control;

	if (!ieee802154_is_data(fc))
		return RX_DROP_UNUSABLE;

	lowpan_get_addr_info_from_hdr(hdr, info);

	return RX_CONTINUE;
}

static void ieee802154_invoke_rx_handlers(struct sk_buff *skb)
{
	struct lowpan_addr_info info = { };
	int res;

#define CALL_RXH(rxh)			\
	do {				\
		res = rxh(skb, &info);	\
		if (res != RX_CONTINUE)	\
			goto rxh_next;	\
	} while (0)

	CALL_RXH(lowpan_rx_h_check);

	lowpan_rx_handlers(skb, &info);
	return;

rxh_next:
	lowpan_rx_handlers_result(skb, res);
}

static int lowpan_rcv(struct sk_buff *skb, struct net_device *wdev,
		      struct packet_type *pt, struct net_device *orig_wdev)
{
	struct net_device *ldev = wdev->ieee802154_ptr->lowpan_dev;

	if (!netif_running(ldev) && !netif_running(wdev))
		goto drop;

	if (wdev->type != ARPHRD_IEEE802154)
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		goto drop;

	skb->dev = ldev;
	ieee802154_invoke_rx_handlers(skb);

	return NET_RX_SUCCESS;
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

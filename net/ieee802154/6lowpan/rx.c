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
#include <net/6lowpan.h>

#include "6lowpan_i.h"
#include "reassembly.h"

static int
lowpan_rx_handlers_result(struct sk_buff *skb, lowpan_rx_result res)
{
	switch (res) {
	case RX_CONTINUE:
		/* packet was not queued should never occur */
		WARN(1, "lowpan: packet wasn't queued or dropped");
	case RX_DROP_UNUSABLE:
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}

static int lowpan_give_skb_to_devices(struct sk_buff *skb,
				      struct net_device *ldev)
{
	ldev->stats.rx_packets++;
	ldev->stats.rx_bytes += skb->len;

	netif_rx(skb);

	return 0;
}

static int lowpan_rx_h_frag(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	int ret;
	const u8 dispatch = *skb_network_header(skb);

	if (!lowpan_is_frag(dispatch))
		return RX_CONTINUE;

	ret = lowpan_frag_rcv(skb, lowpan_get_frag_type(dispatch), info);
	if (ret == 1)
		/* reassmbled fragment contains also
		 * a DISPATCH, check on this.
		 */
		return RX_CONTINUE;

	return RX_QUEUED;
}

static void *lowpan_addr_to_generic(struct lowpan_addr *addr, u8 *mode)
{
	/* TODO remove this handling do __le16 handling in lowpan_process_data */
	/* TODO we shouldn't convert mac values to cpu understandable things */
	switch (addr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		*mode = IEEE802154_ADDR_EXTENDED;
		return &addr->extended_addr;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		*mode = IEEE802154_ADDR_SHORT;
		return &addr->short_addr;
	default:
		/* 6lowpan dataframes should contain real addresses */
		BUG();
	}

	return NULL;
}

static int lowpan_rx_h_iphc(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	u8 iphc0, iphc1, daddr_mode, saddr_mode;
	void *daddr, *saddr;
	int ret;

	if (!lowpan_is_iphc(*skb_network_header(skb)))
		return RX_CONTINUE;

	raw_dump_table(__func__, "raw skb data dump", skb->data, skb->len);

	if (lowpan_fetch_skb(skb, &iphc0, sizeof(iphc0)))
		goto drop;

	if (lowpan_fetch_skb(skb, &iphc1, sizeof(iphc0)))
		goto drop;

	daddr = lowpan_addr_to_generic(&info->daddr, &daddr_mode);
	saddr = lowpan_addr_to_generic(&info->saddr, &saddr_mode);

	ret = lowpan_process_data(skb, skb->dev, saddr, saddr_mode,
				  IEEE802154_ADDR_EXTENDED_LEN, daddr,
				  daddr_mode, IEEE802154_ADDR_EXTENDED_LEN,
				  iphc0, iphc1, lowpan_give_skb_to_devices);
	if (ret < 0)
		return RX_DROP_UNUSABLE;

	return RX_QUEUED;
drop:
	return RX_DROP_UNUSABLE;
}

static int lowpan_rx_h_ipv6(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	int ret;

	if (!lowpan_is_ipv6(*skb_network_header(skb)))
		return RX_CONTINUE;

	/* Pull off the 1-byte of 6lowpan header. */
	if (lowpan_fetch_skb(skb, NULL, 1))
		return RX_DROP_UNUSABLE;

	skb->protocol = htons(ETH_P_IPV6);
	ret = lowpan_give_skb_to_devices(skb, skb->dev);
	if (ret < 0)
		return RX_DROP_UNUSABLE;

	return RX_QUEUED;
}

static int lowpan_rx_h_nalp(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	if (!lowpan_is_nalp(*skb_network_header(skb)))
		return RX_CONTINUE;

	return RX_DROP_UNUSABLE;
}

static int lowpan_rx_h_mesh(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	if (!lowpan_is_mesh(*skb_network_header(skb)))
		return RX_CONTINUE;

	return RX_DROP_UNUSABLE;
}

static int lowpan_rx_h_esc(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	if (!lowpan_is_esc(*skb_network_header(skb)))
		return RX_CONTINUE;

	return RX_DROP_UNUSABLE;
}

static int lowpan_rx_h_hc1(struct sk_buff *skb, struct lowpan_addr_info *info)
{
	if (!lowpan_is_hc1(*skb_network_header(skb)))
		return RX_CONTINUE;

	return RX_DROP_UNUSABLE;
}

static int
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
	CALL_RXH(lowpan_rx_h_nalp);
	CALL_RXH(lowpan_rx_h_iphc);
	CALL_RXH(lowpan_rx_h_ipv6);
	CALL_RXH(lowpan_rx_h_hc1);
	CALL_RXH(lowpan_rx_h_mesh);
	CALL_RXH(lowpan_rx_h_esc);

rxh_next:
	return lowpan_rx_handlers_result(skb, ret);
#undef CALL_RXH
}

static inline void wpan_addr_to_lowpan_addr(struct ieee802154_addr *waddr,
					    struct lowpan_addr *laddr)
{
	switch (waddr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		laddr->extended_addr = swab64(waddr->extended_addr);
		break;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		laddr->short_addr = swab16(waddr->short_addr);
		break;
	default:
		BUG();
	}

	laddr->mode = waddr->mode;
}

static lowpan_rx_result lowpan_rx_h_check(struct sk_buff *skb,
					  struct lowpan_addr_info *info)
{
	if (skb->len < 2)
		return RX_DROP_UNUSABLE;

	/* check on reserved and nalp dispatch value */
	if (lowpan_is_reserved(*skb_mac_header(skb)))
		return RX_DROP_UNUSABLE;

	return RX_CONTINUE;
}

int lowpan_invoke_rx_handlers(struct sk_buff *skb,
				     struct lowpan_addr_info *info)
{
	int res;

#define CALL_RXH(rxh)			\
	do {				\
		res = rxh(skb, info);	\
		if (res != RX_CONTINUE)	\
			goto rxh_next;	\
	} while (0)

	/* frags's contains dispatch again */
	/* TODO remove this stupid handling here */
	CALL_RXH(lowpan_rx_h_frag);
	CALL_RXH(lowpan_rx_h_check);

	return lowpan_rx_handlers(skb, info);

rxh_next:
	return lowpan_rx_handlers_result(skb, res);
}

static inline int
lowpan_get_addr_info_from_hdr(struct ieee802154_hdr *hdr,
			      struct lowpan_addr_info *info)
{
	struct ieee802154_addr daddr, saddr;

	daddr = ieee802154_hdr_daddr(hdr);
	wpan_addr_to_lowpan_addr(&daddr, &info->daddr);

	saddr = ieee802154_hdr_saddr(hdr);
	wpan_addr_to_lowpan_addr(&saddr, &info->saddr);

	if (daddr.pan_id != saddr.pan_id)
		return -EINVAL;

	return 0;
}

static int lowpan_ieee802154_rx_h_check(struct sk_buff *skb,
					struct lowpan_addr_info *info)
{
	struct ieee802154_hdr *hdr;
	__le16 fc;
	int ret;

	hdr = (struct ieee802154_hdr *)skb_mac_header(skb);
	fc = hdr->frame_control;

	if (!ieee802154_is_data(fc))
		return -EINVAL;

	if (ieee802154_is_daddr_none(fc) ||
	    ieee802154_is_saddr_none(fc))
		return -EINVAL;

	ret = lowpan_get_addr_info_from_hdr(hdr, info);
	if (ret < 0)
		return ret;

	return 0;
}

/* ldev should be running, see open_count main.c */
static int lowpan_rcv(struct sk_buff *skb, struct net_device *wdev,
		      struct packet_type *pt, struct net_device *orig_wdev)
{
	struct net_device *ldev = wdev->ieee802154_ptr->lowpan_dev;
	struct lowpan_addr_info info = { };

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	if (wdev->type != ARPHRD_IEEE802154)
		goto drop;

	if (lowpan_ieee802154_rx_h_check(skb, &info) < 0)
		goto drop;

	skb = skb_unshare(skb, GFP_ATOMIC);
	if (!skb)
		goto drop;

	skb->dev = ldev;
	return lowpan_invoke_rx_handlers(skb, &info);
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

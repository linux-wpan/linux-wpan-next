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

#include <net/af_ieee802154.h>
#include <net/cfg802154.h>
#include <net/6lowpan.h>

#include "6lowpan_i.h"
#include "reassembly.h"

static inline struct lowpan_addr_info *
lowpan_skb_priv(const struct sk_buff *skb)
{
	WARN_ON_ONCE(skb_headroom(skb) < sizeof(struct lowpan_addr_info));

	return (struct lowpan_addr_info *)(skb->data -
					   sizeof(struct lowpan_addr_info));
}

int lowpan_header_create(struct sk_buff *skb, struct net_device *ldev,
			 unsigned short type, const void *_daddr,
			 const void *_saddr, unsigned int len)
{
	const u8 *saddr = _saddr;
	const u8 *daddr = _daddr;
	struct lowpan_addr_info *info;

	/* if this package isn't ipv6 one, where should it be routed?
	 * Answer: nowhere.
	 */
	if (type != ETH_P_IPV6) {
		/* dropping */
		kfree_skb(skb);
		return -EINVAL;
	}

	if (!saddr)
		saddr = ldev->dev_addr;

	raw_dump_inline(__func__, "saddr", (unsigned char *)saddr, 8);
	raw_dump_inline(__func__, "daddr", (unsigned char *)daddr, 8);

	info = lowpan_skb_priv(skb);
	if (lowpan_is_addr_broadcast(ldev, daddr)) {
		info->daddr.mode = cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT);
		info->daddr.short_addr = cpu_to_le16(IEEE802154_ADDR_SHORT_BROADCAST);
	} else {
		info->daddr.mode = cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED);
		memcpy(&info->daddr.extended_addr, daddr,
		       IEEE802154_ADDR_EXTENDED_LEN); 
	}
	
	info->saddr.mode = cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED);
	memcpy(&info->saddr.extended_addr, saddr, IEEE802154_ADDR_EXTENDED_LEN);

	return 0;
}

struct lowpan_xmit_cb {
	struct lowpan_dev_info info;
	/* max value should be 1280 */
	u16 dgram_size;
	u16 dgram_offset;
};

static inline struct lowpan_xmit_cb *lowpan_xmit_cb(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(skb->cb) < (sizeof(struct lowpan_xmit_cb)));

	return (struct lowpan_xmit_cb *)(skb->cb);
}

static struct sk_buff*
lowpan_alloc_frag(struct sk_buff *skb, int size,
		  const struct ieee802154_addr *daddr,
		  const struct ieee802154_addr *saddr)
{
	struct net_device *wdev = lowpan_dev_info(skb->dev)->wdev;
	struct wpan_dev *wpan_dev = wdev->ieee802154_ptr;
	struct sk_buff *frag;
	int rc;

	frag = netdev_alloc_skb(wdev, wdev->hard_header_len +
				wdev->needed_tailroom + size);
	if (likely(frag)) {
		frag->priority = skb->priority;
		skb_reserve(frag, wdev->hard_header_len);
		skb_reset_network_header(frag);

		rc = ieee802154_create_h_data(frag, wpan_dev,
					      daddr, saddr, true);
		if (rc < 0) {
			kfree_skb(frag);
			return ERR_PTR(rc);
		}
	} else {
		frag = ERR_PTR(-ENOMEM);
	}

	return frag;
}

static int
lowpan_xmit_fragment(struct sk_buff *skb,
		     u8 *frag_hdr, int frag_hdrlen,
		     int offset, int len,
		     struct ieee802154_addr *daddr,
		     struct ieee802154_addr *saddr)
{
	struct sk_buff *frag;

	raw_dump_inline(__func__, " fragment header", frag_hdr, frag_hdrlen);

	frag = lowpan_alloc_frag(skb, frag_hdrlen + len, daddr, saddr);
	if (IS_ERR(frag))
		return NET_XMIT_DROP;

	memcpy(skb_put(frag, frag_hdrlen), frag_hdr, frag_hdrlen);
	memcpy(skb_put(frag, len), skb_network_header(skb) + offset, len);

	raw_dump_table(__func__, " fragment dump", frag->data, frag->len);

	return dev_queue_xmit(frag);
}

static int
lowpan_xmit_fragmented(struct sk_buff *skb, struct net_device *ldev,
		     struct ieee802154_addr *daddr,
		     struct ieee802154_addr *saddr)
{
	u16 dgram_size, dgram_offset;
	u8 frag_hdr[5];
	int frag_cap, frag_len, payload_cap, rc;
	int skb_unprocessed, skb_offset;
	__be16 frag_tag;

	dgram_size = lowpan_xmit_cb(skb)->dgram_size;
	dgram_offset = lowpan_xmit_cb(skb)->dgram_offset;
	frag_tag = htons(lowpan_dev_info(ldev)->fragment_tag);

	frag_hdr[0] = LOWPAN_DISPATCH_FRAG1 | ((dgram_size >> 8) & 0x07);
	frag_hdr[1] = dgram_size & 0xff;
	memcpy(frag_hdr + 2, &frag_tag, sizeof(frag_tag));
	lowpan_dev_info(ldev)->fragment_tag++;

	payload_cap = ieee802154_max_payload(daddr, saddr, true);

	frag_len = round_down(payload_cap - LOWPAN_FRAG1_HEAD_SIZE -
			      skb_network_header_len(skb), 8);

	skb_offset = skb_network_header_len(skb);
	skb_unprocessed = skb->len - skb_offset;

	rc = lowpan_xmit_fragment(skb, frag_hdr,
				  LOWPAN_FRAG1_HEAD_SIZE, 0,
				  frag_len + skb_network_header_len(skb),
				  daddr, saddr);
	if (rc) {
		pr_debug("%s unable to send FRAG1 packet (tag: %d)",
			 __func__, frag_tag);
		goto err;
	}

	frag_hdr[0] |= LOWPAN_DISPATCH_FRAGN;
	frag_cap = round_down(payload_cap - LOWPAN_FRAGN_HEAD_SIZE, 8);

	do {
		dgram_offset += frag_len;
		skb_offset += frag_len;
		skb_unprocessed -= frag_len;
		frag_len = min(frag_cap, skb_unprocessed);

		frag_hdr[4] = dgram_offset >> 3;

		rc = lowpan_xmit_fragment(skb, frag_hdr,
					  LOWPAN_FRAGN_HEAD_SIZE, skb_offset,
					  frag_len, daddr, saddr);
		if (rc) {
			pr_debug("%s unable to send a FRAGN packet. (tag: %d, offset: %d)\n",
				 __func__, frag_tag, skb_offset);
			goto err;
		}
	} while (skb_unprocessed > frag_cap);

	consume_skb(skb);
	return NETDEV_TX_OK;

err:
	kfree_skb(skb);
	return rc;
}

static void lowpan_addr_to_wpan_addr(struct lowpan_addr *laddr,
				     struct ieee802154_addr *waddr)
{
	switch (laddr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		waddr->extended_addr = swab64(laddr->extended_addr);
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		waddr->short_addr = swab16(laddr->short_addr);
		break;
	default:
		/* other values should never happen */
		BUG();
	}
	
	waddr->mode = laddr->mode;
}

static int lowpan_header(struct sk_buff *skb, struct net_device *ldev,
			 struct lowpan_addr_info *info)
{
	void *daddr, *saddr;

	/* TODO complicated bug why we support extended_addr only */
	daddr = &info->daddr.extended_addr;
	saddr = &info->saddr.extended_addr;
	
	lowpan_xmit_cb(skb)->dgram_size = skb->len;
	lowpan_header_compress(skb, ldev, ETH_P_IPV6, daddr, saddr, skb->len);
	/* saved bytes after compression + lowpan header size */
	lowpan_xmit_cb(skb)->dgram_offset = lowpan_xmit_cb(skb)->dgram_size -
					    skb->len + skb_network_header_len(skb);

	return 0;
}

netdev_tx_t lowpan_xmit(struct sk_buff *skb, struct net_device *ldev)
{
	struct net_device *wdev = lowpan_dev_info(skb->dev)->wdev;
	struct wpan_dev *wpan_dev = wdev->ieee802154_ptr;
	struct lowpan_addr_info info = *lowpan_skb_priv(skb);
	struct ieee802154_addr daddr, saddr;
	int ret, max_single;

	ldev->stats.tx_packets++;
	ldev->stats.tx_bytes += skb->len;

	pr_debug("package xmit\n");

	/* prepare wpan address data */
	lowpan_addr_to_wpan_addr(&info.daddr, &daddr);
	lowpan_addr_to_wpan_addr(&info.saddr, &saddr);
	/* intra-PAN communications */
	saddr.pan_id = wpan_dev->pan_id;
	daddr.pan_id = saddr.pan_id;

	max_single = ieee802154_max_payload(&daddr, &saddr, true);
	if (max_single < 0) {
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}	       

	/* check on current length with ipv6 dispatch */
	/* TODO make this configureable via sysctl */
	if (skb->len + 1 <= max_single) {
		const u8 ipv6_dispatch = LOWPAN_DISPATCH_IPV6;

		memcpy(skb_push(skb, sizeof(ipv6_dispatch)), &ipv6_dispatch,
		       sizeof(ipv6_dispatch));

		ret = ieee802154_create_h_data(skb, wpan_dev, &daddr, &saddr, true);
		if (ret < 0) {
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}

		skb->dev = wdev;
		return dev_queue_xmit(skb);
	} else {
		skb = skb_unshare(skb, GFP_ATOMIC);
		if (!skb)
			return NETDEV_TX_OK;

		ret = lowpan_header(skb, ldev, &info);
		if (ret < 0) {
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}

		if (skb->len <= max_single) {
			ret = ieee802154_create_h_data(skb, wpan_dev, &daddr, &saddr, true);
			if (ret < 0) {
				kfree_skb(skb);
				return NETDEV_TX_OK;
			}

			skb->dev = wdev;
			return dev_queue_xmit(skb);
		} else {
			pr_debug("frame is too big, fragmentation is needed\n");
			return lowpan_xmit_fragmented(skb, ldev, &daddr, &saddr);
		}
	}
}

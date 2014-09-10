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
#include <net/ieee802154_netdev.h>
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

	/* TODO ask david or marc if this run into trouble */
	info = lowpan_skb_priv(skb);

	/* TODO need to be handled like this, we don't support short address right now */
#if 0
	if (lowpan_is_addr_broadcast(ldev, daddr)) {
		info->daddr.mode = cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT);
		memcpy(&info->daddr.addr.short_, saddr,
		       IEEE802154_SHORT_ADDR_LEN); 
	} else {
		info->daddr.mode = cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED);
		memcpy(&info->daddr.addr.extended, daddr,
		       IEEE802154_EXTENDED_ADDR_LEN); 
	}
#endif
	info->daddr.mode = cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED);
	memcpy(&info->daddr.u.extended, daddr, IEEE802154_EXTENDED_ADDR_LEN);

	info->saddr.mode = cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED);
	memcpy(&info->saddr.u.extended, saddr, IEEE802154_EXTENDED_ADDR_LEN);

	return 0;
}

static struct sk_buff*
lowpan_alloc_frag(struct sk_buff *skb, int size,
		  const struct ieee802154_hdr *master_hdr)
{
	struct net_device *wdev = lowpan_dev_info(skb->dev)->wdev;
	struct sk_buff *frag;
	int rc;

	frag = alloc_skb(wdev->hard_header_len +
			 wdev->needed_tailroom + size,
			 GFP_ATOMIC);

	if (likely(frag)) {
		frag->dev = wdev;
		frag->priority = skb->priority;
		skb_reserve(frag, wdev->hard_header_len);
		skb_reset_network_header(frag);
		*mac_cb(frag) = *mac_cb(skb);

		rc = dev_hard_header(frag, wdev, 0, &master_hdr->dest,
				     &master_hdr->source, size);
		if (rc < 0) {
			kfree_skb(frag);
			return ERR_PTR(-rc);
		}
	} else {
		frag = ERR_PTR(-ENOMEM);
	}

	return frag;
}

static int
lowpan_xmit_fragment(struct sk_buff *skb, const struct ieee802154_hdr *wpan_hdr,
		     u8 *frag_hdr, int frag_hdrlen,
		     int offset, int len)
{
	struct sk_buff *frag;

	raw_dump_inline(__func__, " fragment header", frag_hdr, frag_hdrlen);

	frag = lowpan_alloc_frag(skb, frag_hdrlen + len, wpan_hdr);
	if (IS_ERR(frag))
		return -PTR_ERR(frag);

	memcpy(skb_put(frag, frag_hdrlen), frag_hdr, frag_hdrlen);
	memcpy(skb_put(frag, len), skb_network_header(skb) + offset, len);

	raw_dump_table(__func__, " fragment dump", frag->data, frag->len);

	return dev_queue_xmit(frag);
}

static int
lowpan_xmit_fragmented(struct sk_buff *skb, struct net_device *ldev,
		       const struct ieee802154_hdr *wpan_hdr)
{
	u16 dgram_size, dgram_offset;
	__be16 frag_tag;
	u8 frag_hdr[5];
	int frag_cap, frag_len, payload_cap, rc;
	int skb_unprocessed, skb_offset;

	dgram_size = lowpan_uncompress_size(skb, &dgram_offset) -
		     skb->mac_len;
	frag_tag = lowpan_dev_info(ldev)->fragment_tag++;

	frag_hdr[0] = LOWPAN_DISPATCH_FRAG1 | ((dgram_size >> 8) & 0x07);
	frag_hdr[1] = dgram_size & 0xff;
	memcpy(frag_hdr + 2, &frag_tag, sizeof(frag_tag));

	payload_cap = ieee802154_max_payload(wpan_hdr);

	frag_len = round_down(payload_cap - LOWPAN_FRAG1_HEAD_SIZE -
			      skb_network_header_len(skb), 8);

	skb_offset = skb_network_header_len(skb);
	skb_unprocessed = skb->len - skb->mac_len - skb_offset;

	rc = lowpan_xmit_fragment(skb, wpan_hdr, frag_hdr,
				  LOWPAN_FRAG1_HEAD_SIZE, 0,
				  frag_len + skb_network_header_len(skb));
	if (rc) {
		pr_debug("%s unable to send FRAG1 packet (tag: %d)",
			 __func__, frag_tag);
		goto err;
	}

	frag_hdr[0] &= ~LOWPAN_DISPATCH_FRAG1;
	frag_hdr[0] |= LOWPAN_DISPATCH_FRAGN;
	frag_cap = round_down(payload_cap - LOWPAN_FRAGN_HEAD_SIZE, 8);

	do {
		dgram_offset += frag_len;
		skb_offset += frag_len;
		skb_unprocessed -= frag_len;
		frag_len = min(frag_cap, skb_unprocessed);

		frag_hdr[4] = dgram_offset >> 3;

		rc = lowpan_xmit_fragment(skb, wpan_hdr, frag_hdr,
					  LOWPAN_FRAGN_HEAD_SIZE, skb_offset,
					  frag_len);
		if (rc) {
			pr_debug("%s unable to send a FRAGN packet. (tag: %d, offset: %d)\n",
				 __func__, frag_tag, skb_offset);
			goto err;
		}
	} while (skb_unprocessed > frag_cap);

	consume_skb(skb);
	return NET_XMIT_SUCCESS;

err:
	kfree_skb(skb);
	return rc;
}

static int lowpan_header(struct sk_buff *skb, struct net_device *ldev)
{
	struct net_device *wdev = lowpan_dev_info(skb->dev)->wdev;
	struct wpan_dev *wpan_dev = wdev->ieee802154_ptr;
	struct ieee802154_addr sa, da;
	struct ieee802154_mac_cb *cb = mac_cb_init(skb);
	struct lowpan_addr_info info;
	void *daddr, *saddr;

	memcpy(&info, lowpan_skb_priv(skb), sizeof(info));

	/* TODO complicated bug why we support extended_addr only */
	daddr = &info.daddr.u.extended;
	saddr = &info.saddr.u.extended;
	
	lowpan_header_compress(skb, ldev, ETH_P_IPV6, daddr, saddr, skb->len);

	/* NOTE1: I'm still unsure about the fact that compression and WPAN
	 * header are created here and not later in the xmit. So wait for
	 * an opinion of net maintainers.
	 */
	/* NOTE2: to be absolutely correct, we must derive PANid information
	 * from MAC subif of the 'ldev' and 'wdev' network devices, but
	 * this isn't implemented in mainline yet, so currently we assign 0xff
	 */
	cb->type = IEEE802154_FC_TYPE_DATA;

	/* prepare wpan address data */
	sa.mode = IEEE802154_ADDR_LONG;
	sa.pan_id = wpan_dev->pan_id;
	sa.extended_addr = ieee802154_devaddr_from_raw(saddr);

	/* intra-PAN communications */
	da.pan_id = sa.pan_id;

	/* if the destination address is the broadcast address, use the
	 * corresponding short address
	 */
	if (lowpan_is_addr_broadcast(ldev, daddr)) {
		da.mode = IEEE802154_ADDR_SHORT;
		da.short_addr = cpu_to_le16(IEEE802154_ADDR_BROADCAST);
		cb->ackreq = false;
	} else {
		da.mode = IEEE802154_ADDR_LONG;
		da.extended_addr = ieee802154_devaddr_from_raw(daddr);
		cb->ackreq = true;
	}

	return dev_hard_header(skb, lowpan_dev_info(ldev)->wdev,
			ETH_P_IPV6, (void *)&da, (void *)&sa, 0);
}

netdev_tx_t lowpan_xmit(struct sk_buff *skb, struct net_device *ldev)
{
	struct ieee802154_hdr wpan_hdr;
	int max_single, ret;

	ldev->stats.rx_packets++;
	ldev->stats.rx_bytes += skb->len;

	pr_debug("package xmit\n");
	ret = lowpan_header(skb, ldev);
	if (ret < 0) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	if (ieee802154_hdr_peek(skb, &wpan_hdr) < 0) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	max_single = ieee802154_max_payload(&wpan_hdr);

	if (skb_tail_pointer(skb) - skb_network_header(skb) <= max_single) {
		skb->dev = lowpan_dev_info(ldev)->wdev;
		return dev_queue_xmit(skb);
	} else {
		netdev_tx_t rc;

		pr_debug("frame is too big, fragmentation is needed\n");
		rc = lowpan_xmit_fragmented(skb, ldev, &wpan_hdr);

		return rc < 0 ? NET_XMIT_DROP : rc;
	}
}

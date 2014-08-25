/*
 * Copyright (C) 2007-2012 Siemens AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Written by:
 * Pavel Smolenskiy <pavel.smolenskiy@gmail.com>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#include <linux/crc-ccitt.h>
#include <net/rtnetlink.h>
#include <linux/nl802154.h>

#include <net/mac802154.h>
#include <net/ieee802154_netdev.h>

#include "ieee802154_i.h"

static void ieee802154_rx_handlers_result(struct ieee802154_rx_data *rx,
					  ieee802154_rx_result res)
{
	switch (res) {
	case RX_DROP_UNUSABLE:
		kfree_skb(rx->skb);
		break;
	}
}

static void ieee802154_deliver_skb(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;

	skb->protocol = htons(ETH_P_IEEE802154);
	netif_receive_skb(skb);
}

static ieee802154_rx_result
ieee802154_rx_h_beacon(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc;

	fc = ((struct ieee802154_hdr_data *)skb->data)->frame_control;

	/* Maybe useful for raw sockets? -> monitor vif type only */
	if (ieee802154_is_beacon(fc))
		return RX_DROP_UNUSABLE;

	return RX_CONTINUE;
}

static ieee802154_rx_result
ieee802154_rx_h_data(struct ieee802154_rx_data *rx)
{
	struct ieee802154_sub_if_data *sdata = rx->sdata;
	struct net_device *dev = sdata->dev;
	struct ieee802154_hdr_data *hdr;
	union ieee802154_addr_foo *src, *dest;
	struct sk_buff *skb = rx->skb;
	__le16 fc, *src_pan_id;
	u16 hdr_len = 5;

	fc = ((struct ieee802154_hdr_data *)skb->data)->frame_control;

	if (!ieee802154_is_data(fc))
		return RX_CONTINUE;

	/* dataframes should have short and extended address */
	if (ieee802154_is_daddr_none(fc) ||
	    ieee802154_is_saddr_none(fc))
		return RX_DROP_UNUSABLE;

	hdr = (struct ieee802154_hdr_data *)skb_mac_header(skb);

	src_pan_id = ieee802154_hdr_data_src_pan_id(hdr);
	dest = ieee802154_hdr_data_dest_addr(hdr);
	src = ieee802154_hdr_data_src_addr(hdr);

	/* check if source pan_id is broadcast */
	if (*src_pan_id == cpu_to_le16(IEEE802154_PAN_ID_BROADCAST))
		return RX_DROP_UNUSABLE;

	if (ieee802154_is_daddr_extended(fc)) {
		if (!ieee802154_is_valid_extended_addr(
		    &dest->extended_addr))
			return RX_DROP_UNUSABLE;

		hdr_len += IEEE802154_EXTENDED_ADDR_LEN;
	} else {
		hdr_len += IEEE802154_SHORT_ADDR_LEN;
	}

	if (ieee802154_is_saddr_extended(fc)) {
		if (!ieee802154_is_valid_extended_addr(
		    &src->extended_addr))
			return RX_DROP_UNUSABLE;

		hdr_len += IEEE802154_EXTENDED_ADDR_LEN;
	} else {
		if (src->short_addr ==
		    cpu_to_le16(IEEE802154_SHORT_ADDR_BROADCAST))
			return RX_DROP_UNUSABLE;

		hdr_len += IEEE802154_SHORT_ADDR_LEN;
	}

	if (ieee802154_is_intra_pan(fc))
		hdr_len += 2;
	else
		hdr_len += 4;

	skb_set_network_header(skb, hdr_len);

	if (hdr->dest_pan_id != sdata->wpan_dev.pan_id &&
	    hdr->dest_pan_id != cpu_to_le16(IEEE802154_PAN_ID_BROADCAST)) {
		skb->pkt_type = PACKET_OTHERHOST;
		goto deliver;
	}

	if (ieee802154_is_daddr_short(fc)) {
		if (dest->short_addr ==
		    cpu_to_le16(IEEE802154_SHORT_ADDR_BROADCAST))
			skb->pkt_type = PACKET_BROADCAST;
		else if (dest->short_addr == sdata->short_addr)
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
	} else {
		/* else branch, because it can be only short xor extended */
		if (dest->extended_addr == sdata->extended_addr)
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
	}

deliver:
	skb->dev = dev;
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;

	ieee802154_deliver_skb(rx);

	return RX_QUEUED;
}

static ieee802154_rx_result
ieee802154_rx_h_ack(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc;

	fc = ((struct ieee802154_hdr_data *)skb->data)->frame_control;

	/* Maybe useful for raw sockets? -> monitor vif type only */
	if (ieee802154_is_ack(fc))
		return RX_DROP_UNUSABLE;

	return RX_CONTINUE;
}

static ieee802154_rx_result
ieee802154_rx_h_cmd(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc;

	fc = ((struct ieee802154_hdr_data *)skb->data)->frame_control;

	/* Maybe useful for raw sockets? -> monitor vif type only */
	if (ieee802154_is_cmd(fc))
		return RX_DROP_UNUSABLE;

	return RX_CONTINUE;
}

static void ieee802154_rx_handlers(struct ieee802154_rx_data *rx)
{
	ieee802154_rx_result res;

#define CALL_RXH(rxh)			\
	do {				\
		res = rxh(rx);		\
		if (res != RX_CONTINUE)	\
			goto rxh_next;	\
	} while (0)

	CALL_RXH(ieee802154_rx_h_data);
	CALL_RXH(ieee802154_rx_h_ack);
	CALL_RXH(ieee802154_rx_h_beacon);
	CALL_RXH(ieee802154_rx_h_cmd);

rxh_next:
	ieee802154_rx_handlers_result(rx, res);

#undef CALL_RXH
}

static ieee802154_rx_result
ieee802154_rx_h_check(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc;

	fc = ((struct ieee802154_hdr_foo *)skb->data)->frame_control;

	/* check on reserved frame type */
	if (ieee802154_is_reserved(fc))
		return RX_DROP_UNUSABLE;

	/* check on reserved address types */
	if (ieee802154_is_daddr_reserved(fc) ||
	    ieee802154_is_saddr_reserved(fc))
		return RX_DROP_UNUSABLE;

	/* if it's not ack and saddr is zero, dest
	 * should be non zero */
	if (!ieee802154_is_ack(fc) && ieee802154_is_saddr_none(fc) &&
	    ieee802154_is_daddr_none(fc))
		return RX_DROP_UNUSABLE;

	skb_reset_mac_header(rx->skb);

	return RX_CONTINUE;
}

static void ieee802154_invoke_rx_handlers(struct ieee802154_rx_data *rx)
{
	int res;

#define CALL_RXH(rxh)			\
	do {				\
		res = rxh(rx);		\
		if (res != RX_CONTINUE)	\
			goto rxh_next;	\
	} while (0)

	CALL_RXH(ieee802154_rx_h_check);

	ieee802154_rx_handlers(rx);
	return;

rxh_next:
	ieee802154_rx_handlers_result(rx, res);

#undef CALL_RXH
}

/* This is the actual Rx frames handler. as it belongs to Rx path it must
 * be called with rcu_read_lock protection.
 */
static void
__ieee802154_rx_handle_packet(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	struct ieee802154_local *local = hw_to_local(hw);
	struct ieee802154_sub_if_data *sdata;
	struct ieee802154_rx_data rx = { };

	rx.skb = skb;
	rx.local = local;

	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		if (!ieee802154_sdata_running(sdata))
			continue;

		if (sdata->vif.type == NL802154_IFTYPE_MONITOR)
			continue;

		rx.sdata = sdata;
		ieee802154_invoke_rx_handlers(&rx);
	}
}

void ieee802154_rx(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	WARN_ON_ONCE(softirq_count() == 0);

	/* TODO this don't work for FCS with monitor vifs
	 * also some drivers don't deliver with crc and drop
	 * it on driver layer, something is wrong here. */
	if (!(hw->flags & IEEE802154_HW_OMIT_CKSUM)) {
		u16 crc;

		crc = crc_ccitt(0, skb->data, skb->len);
		if (crc)
			goto drop;
		/* remove the crc from frame */
		skb_trim(skb, skb->len - 2);
	}

	rcu_read_lock();
	
	__ieee802154_rx_handle_packet(hw, skb);
	
	rcu_read_unlock();

	return;

drop:
	kfree_skb(skb);
}
EXPORT_SYMBOL(ieee802154_rx);

void
ieee802154_rx_irqsafe(struct ieee802154_hw *hw, struct sk_buff *skb, u8 lqi)
{
	struct ieee802154_local *local = hw_to_local(hw);

	/* TODO should be accesable via netlink like scan dump */
	mac_cb(skb)->lqi = lqi;
	skb->pkt_type = IEEE802154_RX_MSG;
	skb_queue_tail(&local->skb_queue, skb);
	tasklet_schedule(&local->tasklet);
}
EXPORT_SYMBOL(ieee802154_rx_irqsafe);

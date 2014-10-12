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
#include <linux/netdevice.h>
#include <linux/crc-ccitt.h>
#include <linux/nl802154.h>

#include <net/mac802154.h>

#include "ieee802154_i.h"

static void ieee802154_rx_handlers_result(struct ieee802154_rx_data *rx,
					  ieee802154_rx_result res)
{
	switch (res) {
	case RX_CONTINUE:
		/* frame was not queued should never occur */
		WARN(1, "mac802154: frame wasn't queued or dropped");
	case RX_DROP_UNUSABLE:
		kfree_skb(rx->skb);
		break;
	}
}

static void ieee802154_deliver_skb(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->protocol = htons(ETH_P_IEEE802154);
	netif_receive_skb(skb);
}

static ieee802154_rx_result
ieee802154_rx_h_beacon(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc;

	fc = ((struct ieee802154_hdr *)skb->data)->frame_control;

	/* Maybe useful for raw sockets? -> monitor vif type only */
	if (ieee802154_is_beacon(fc))
		return RX_DROP_UNUSABLE;

	return RX_CONTINUE;
}

static ieee802154_rx_result
ieee802154_rx_h_data(struct ieee802154_rx_data *rx)
{
	struct ieee802154_sub_if_data *sdata = rx->sdata;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct net_device *dev = sdata->dev;
	struct ieee802154_hdr *hdr;
	struct ieee802154_addr saddr, daddr;
	struct sk_buff *skb = rx->skb;
	__le16 fc;
	u16 hdr_len = 5;

	hdr = (struct ieee802154_hdr *)skb_mac_header(skb);
	fc = hdr->frame_control;

	if (!ieee802154_is_data(fc))
		return RX_CONTINUE;

	/* parse daddr address */
	daddr = ieee802154_hdr_daddr(hdr);
	if (!ieee802154_is_valid_daddr(&daddr))
		return RX_DROP_UNUSABLE;

	/* parse saddr address */
	saddr = ieee802154_hdr_saddr(hdr);
	if (!ieee802154_is_valid_saddr(&saddr))
		return RX_DROP_UNUSABLE;

	switch (daddr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		if (likely(daddr.extended_addr == wpan_dev->extended_addr))
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;

		hdr_len += IEEE802154_ADDR_EXTENDED_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		if (ieee802154_is_short_broadcast(daddr.short_addr))
			skb->pkt_type = PACKET_BROADCAST;
		else if (daddr.short_addr == wpan_dev->short_addr)
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;

		hdr_len += IEEE802154_ADDR_SHORT_LEN;
		break;
	default:
		/* reserved and none should never happen */
		BUG();
	}

	switch (saddr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		hdr_len += IEEE802154_ADDR_EXTENDED_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		hdr_len += IEEE802154_ADDR_SHORT_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		/* 802.15.4-2011 comment:
		 * If only source addressing fields are included in a data
		 * or MAC command frame, the frame shall be accepted only
		 * if the device is the PAN coordinator and the source PAN
		 * identifier matches macPANId.
		 */
		if (saddr.pan_id == wpan_dev->pan_id &&
		    wpan_dev_is_coord(wpan_dev))
			skb->pkt_type = PACKET_HOST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	default:
		/* reserved should never happen */
		BUG();
	}

	/* add src pan length */
	if (!ieee802154_is_intra_pan(fc))
		hdr_len += IEEE802154_PAN_ID_LEN;

	if (!ieee802154_is_pan_broadcast(daddr.pan_id) &&
	    daddr.pan_id != wpan_dev->pan_id)
		skb->pkt_type = PACKET_OTHERHOST;

	skb->dev = dev;
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;

	/* remove mac header */
	skb_pull(skb, hdr_len);
	/* remove crc */
	skb_trim(skb, skb->len - IEEE802154_FCS_LEN);

	ieee802154_deliver_skb(rx);

	return RX_QUEUED;
}

static ieee802154_rx_result
ieee802154_rx_h_ack(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc;

	fc = ((struct ieee802154_hdr *)skb->data)->frame_control;

	/* Maybe useful for raw sockets? -> monitor vif type only */
	if (ieee802154_is_ack(fc)) {
		if (!(rx->local->hw.flags & IEEE802154_HW_AACK))
			WARN_ONCE(1, "ACK frame received. Handling via PHY MAC sublayer only.\n");

		return RX_DROP_UNUSABLE;
	}

	return RX_CONTINUE;
}

static ieee802154_rx_result
ieee802154_rx_h_cmd(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc;

	fc = ((struct ieee802154_hdr *)skb->data)->frame_control;

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
	CALL_RXH(ieee802154_rx_h_beacon);
	CALL_RXH(ieee802154_rx_h_cmd);
	/* unlikely */
	CALL_RXH(ieee802154_rx_h_ack);

rxh_next:
	ieee802154_rx_handlers_result(rx, res);

#undef CALL_RXH
}

static ieee802154_rx_result
ieee802154_rx_h_check(struct ieee802154_rx_data *rx)
{
	struct sk_buff *skb = rx->skb;
	__le16 fc, crc;

	/* check if transceiver doesn't valid checksum, we validate
	 * the checksum here.
	 */
	if (!(rx->local->hw.flags & IEEE802154_HW_FILT_CKSUM)) {
		memcpy(&crc, skb_tail_pointer(skb) - sizeof(crc), sizeof(crc));
		if (!crc_ccitt(le16_to_cpu(crc), skb->data,
			       skb->len - sizeof(crc)))
			return RX_DROP_UNUSABLE;
	}

	fc = ((struct ieee802154_hdr *)skb->data)->frame_control;

	/* check on reserved frame type and version */
	if (unlikely(ieee802154_is_reserved(fc) ||
		     ieee802154_is_vers_reserved(fc)))
		return RX_DROP_UNUSABLE;

	/* check on reserved address types */
	if (unlikely(ieee802154_is_daddr_reserved(fc) ||
		     ieee802154_is_saddr_reserved(fc)))
		return RX_DROP_UNUSABLE;

#if 0
	TODO should handled by all frame handlers
	/* if it's not ack and saddr is zero, dest
	 * should be non zero */
	if (unlikely(!ieee802154_is_ack(fc) && ieee802154_is_saddr_none(fc) &&
		     !ieee802154_is_daddr_none(fc)))
		return RX_DROP_UNUSABLE;
#endif

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
	struct sk_buff *skb2;

	rx.local = local;

	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		if (!ieee802154_sdata_running(sdata))
			continue;

		if (sdata->vif.type == NL802154_IFTYPE_MONITOR)
			continue;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2) {
			rx.skb = skb2;
			rx.sdata = sdata;
			ieee802154_invoke_rx_handlers(&rx);
		}
	}
}

static void
ieee802154_rx_monitor(struct ieee802154_local *local, struct sk_buff *skb)
{
	struct ieee802154_sub_if_data *sdata;
	struct sk_buff *skb2;

	skb_reset_mac_header(skb);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = htons(ETH_P_IEEE802154);

	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		if (sdata->vif.type != NL802154_IFTYPE_MONITOR)
			continue;

		if (!ieee802154_sdata_running(sdata))
			continue;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2) {
			skb2->dev = sdata->dev;
			netif_receive_skb(skb2);

			sdata->dev->stats.rx_packets++;
			sdata->dev->stats.rx_bytes += skb->len;
		}
	}
}

void ieee802154_rx(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	struct ieee802154_local *local = hw_to_local(hw);

	WARN_ON_ONCE(softirq_count() == 0);

	rcu_read_lock();

	/* Add crc checksum, required by monitor. We calculate some, here.
	 * TODO: this is an ugly handling because we need transmitted crc
	 * here.
	 */
	if (hw->flags & IEEE802154_HW_RX_OMIT_CKSUM) {
		__le16 crc = cpu_to_le16(crc_ccitt(0, skb->data, skb->len));
		memcpy(skb_put(skb, sizeof(crc)), &crc, sizeof(crc));
	}

	ieee802154_rx_monitor(local, skb);
	__ieee802154_rx_handle_packet(hw, skb);
	
	rcu_read_unlock();

	consume_skb(skb);
}
EXPORT_SYMBOL(ieee802154_rx);

void
ieee802154_rx_irqsafe(struct ieee802154_hw *hw, struct sk_buff *skb, u8 lqi)
{
	struct ieee802154_local *local = hw_to_local(hw);

	/* TODO should be accesable via netlink like scan dump */
	//mac_cb(skb)->lqi = lqi;
	skb->pkt_type = IEEE802154_RX_MSG;
	skb_queue_tail(&local->skb_queue, skb);
	tasklet_schedule(&local->tasklet);
}
EXPORT_SYMBOL(ieee802154_rx_irqsafe);

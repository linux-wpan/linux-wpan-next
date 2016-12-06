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
 * Based on: net/mac80211/util.c
 */

#include <net/mac802154.h>

#include "ieee802154_i.h"
#include "driver-ops.h"
#include "node_info.h"

/* privid for wpan_phys to determine whether they belong to us or not */
const void *const mac802154_wpan_phy_privid = &mac802154_wpan_phy_privid;

void ieee802154_wake_queue(struct ieee802154_hw *hw)
{
	struct ieee802154_local *local = hw_to_local(hw);
	struct ieee802154_sub_if_data *sdata;

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		if (!sdata->dev)
			continue;

		netif_wake_queue(sdata->dev);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(ieee802154_wake_queue);

void ieee802154_stop_queue(struct ieee802154_hw *hw)
{
	struct ieee802154_local *local = hw_to_local(hw);
	struct ieee802154_sub_if_data *sdata;

	rcu_read_lock();
	list_for_each_entry_rcu(sdata, &local->interfaces, list) {
		if (!sdata->dev)
			continue;

		netif_stop_queue(sdata->dev);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(ieee802154_stop_queue);

enum hrtimer_restart ieee802154_xmit_ifs_timer(struct hrtimer *timer)
{
	struct ieee802154_local *local =
		container_of(timer, struct ieee802154_local, ifs_timer);

	ieee802154_wake_queue(&local->hw);

	return HRTIMER_NORESTART;
}

void ieee802154_xmit_complete(struct ieee802154_hw *hw, struct sk_buff *skb,
			      bool ifs_handling, enum ieee802154_tx_status status)
{
	int hlen;
	struct ieee802154_hdr hdr;

	hlen = ieee802154_hdr_pull(skb, &hdr);
	if (hlen > 0) {
		struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(skb->dev);
		/* TODO check on ack_request */
		switch (hdr.dest.mode) {
		case IEEE802154_ADDR_LONG:
			node_info_tx_insert_or_update(sdata->local,
						      &hdr.dest.extended_addr,
						      status, hdr.fc.ack_request);
			break;
		case IEEE802154_ADDR_SHORT:
			if (hdr.dest.short_addr == cpu_to_le16(0xffff)) {
				node_info_tx_broadcast(sdata->local, status);
			}
		default:
			break;
		}
	}

	if (ifs_handling) {
		struct ieee802154_local *local = hw_to_local(hw);
		u8 max_sifs_size;

		/* If transceiver sets CRC on his own we need to use lifs
		 * threshold len above 16 otherwise 18, because it's not
		 * part of skb->len.
		 */
		if (hw->flags & IEEE802154_HW_TX_OMIT_CKSUM)
			max_sifs_size = IEEE802154_MAX_SIFS_FRAME_SIZE -
					IEEE802154_FCS_LEN;
		else
			max_sifs_size = IEEE802154_MAX_SIFS_FRAME_SIZE;

		if (skb->len > max_sifs_size)
			hrtimer_start(&local->ifs_timer,
				      ktime_set(0, hw->phy->lifs_period * NSEC_PER_USEC),
				      HRTIMER_MODE_REL);
		else
			hrtimer_start(&local->ifs_timer,
				      ktime_set(0, hw->phy->sifs_period * NSEC_PER_USEC),
				      HRTIMER_MODE_REL);
	} else {
		ieee802154_wake_queue(hw);
	}

	dev_consume_skb_any(skb);
}
EXPORT_SYMBOL(ieee802154_xmit_complete);

void ieee802154_stop_device(struct ieee802154_local *local)
{
	flush_workqueue(local->workqueue);
	hrtimer_cancel(&local->ifs_timer);
	drv_stop(local);
}

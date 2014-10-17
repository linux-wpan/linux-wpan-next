/*
 * Copyright 2007-2012 Siemens AG
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Sergey Lapin <slapin@ossfans.org>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/crc-ccitt.h>

#include <net/mac802154.h>
#include <net/cfg802154.h>

#include "ieee802154_i.h"
#include "driver-ops.h"

/* IEEE 802.15.4 transceivers can sleep during the xmit session, so process
 * packets through the workqueue.
 */
struct ieee802154_xmit_cb {
	struct sk_buff *skb;
	struct work_struct work;
	struct ieee802154_local *local;
};

static inline struct ieee802154_xmit_cb *
ieee802154_xmit_cb(const struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(skb->cb) < sizeof(struct ieee802154_xmit_cb));

	return (struct ieee802154_xmit_cb *)skb->cb;
}

static void ieee802154_xmit_worker(struct work_struct *work)
{
	struct ieee802154_xmit_cb *cb =
		container_of(work, struct ieee802154_xmit_cb, work);
	struct ieee802154_local *local = cb->local;
	struct sk_buff *skb = cb->skb;
	int ret;

	/* avoid a ifdown while transmit */
	rtnl_lock();

	if (!netif_running(skb->dev))
		goto err_tx;

	ret = drv_xmit_sync(local, skb);
	if (ret)
		goto err_tx;

	rtnl_unlock();

	/* Restart the netif queue on each sub_if_data object. */
	ieee802154_xmit_complete(&local->hw, skb);

	skb->dev->stats.tx_packets++;
	skb->dev->stats.tx_bytes += skb->len;

	return;

err_tx:
	rtnl_unlock();
	pr_debug("transmission failed\n");
	ieee802154_wake_queue(&local->hw);
	kfree_skb(skb);
}

static netdev_tx_t
ieee802154_tx(struct ieee802154_local *local, struct sk_buff *skb)
{
	struct ieee802154_xmit_cb *cb = ieee802154_xmit_cb(skb);
	int ret;

	if (skb_cow_head(skb, local->hw.extra_tx_headroom)) {
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	skb->skb_iif = skb->dev->ifindex;

	/* Stop the netif queue on each sub_if_data object. */
	ieee802154_stop_queue(&local->hw);

	/* async is priority, otherwise sync is fallback */
	if (local->ops->xmit_async) {
		ret = drv_xmit_async(local, skb);
		if (ret) {
			ieee802154_wake_queue(&local->hw);
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}

		skb->dev->stats.tx_packets++;
		skb->dev->stats.tx_bytes += skb->len;

		return NETDEV_TX_OK;
	}

	INIT_WORK(&cb->work, ieee802154_xmit_worker);
	cb->skb = skb;
	cb->local = local;

	queue_work(local->workqueue, &cb->work);

	return NETDEV_TX_OK;
}

netdev_tx_t ieee802154_monitor_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	return ieee802154_tx(sdata->local, skb);
}

netdev_tx_t ieee802154_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_local *local = sdata->local;
#if 0
	int ret;

	ret = mac802154_llsec_encrypt(&sdata->sec, skb);
	if (ret) {
		pr_warn("encryption failed: %d\n", ret);
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}
#endif

	if (!(local->hw.flags & IEEE802154_HW_TX_OMIT_CKSUM)) {
		__le16 crc = cpu_to_le16(crc_ccitt(0, skb->data, skb->len));
		memcpy(skb_put(skb, sizeof(crc)), &crc, sizeof(crc));
	}

	return ieee802154_tx(local, skb);
}

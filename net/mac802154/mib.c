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

#include <linux/if_arp.h>

#include <net/mac802154.h>
#include <net/ieee802154_netdev.h>
#include <net/cfg802154.h>

#include "ieee802154_i.h"

struct phy_chan_notify_work {
	struct work_struct work;
	struct net_device *dev;
};

struct hw_addr_filt_notify_work {
	struct work_struct work;
	struct net_device *dev;
	unsigned long changed;
};

static struct ieee802154_local *mac802154_slave_get_priv(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	return sdata->local;
}

static void hw_addr_notify(struct work_struct *work)
{
	struct hw_addr_filt_notify_work *nw = container_of(work,
			struct hw_addr_filt_notify_work, work);
	struct ieee802154_local *local = mac802154_slave_get_priv(nw->dev);
	int res;

	res = local->ops->set_hw_addr_filt(&local->hw, &local->hw.hw_filt,
					   nw->changed);
	if (res)
		pr_debug("failed changed mask %lx\n", nw->changed);

	kfree(nw);
}

static void set_hw_addr_filt(struct net_device *dev, unsigned long changed)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct hw_addr_filt_notify_work *work;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return;

	INIT_WORK(&work->work, hw_addr_notify);
	work->dev = dev;
	work->changed = changed;
	queue_work(sdata->local->dev_workqueue, &work->work);
}

void mac802154_dev_set_short_addr(struct net_device *dev, __le16 val)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&sdata->mib_lock);
	sdata->short_addr = val;
	spin_unlock_bh(&sdata->mib_lock);

	if ((sdata->local->ops->set_hw_addr_filt) &&
	    (sdata->local->hw.hw_filt.short_addr != sdata->short_addr)) {
		sdata->local->hw.hw_filt.short_addr = sdata->short_addr;
		set_hw_addr_filt(dev, IEEE802154_AFILT_SADDR_CHANGED);
	}
}

__le16 mac802154_dev_get_short_addr(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	__le16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&sdata->mib_lock);
	ret = sdata->short_addr;
	spin_unlock_bh(&sdata->mib_lock);

	return ret;
}

void mac802154_dev_set_ieee_addr(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_local *local = sdata->local;

	sdata->extended_addr = ieee802154_devaddr_from_raw(dev->dev_addr);

	if (local->ops->set_hw_addr_filt &&
	    local->hw.hw_filt.ieee_addr != sdata->extended_addr) {
		local->hw.hw_filt.ieee_addr = sdata->extended_addr;
		set_hw_addr_filt(dev, IEEE802154_AFILT_IEEEADDR_CHANGED);
	}
}

__le16 mac802154_dev_get_pan_id(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	__le16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&sdata->mib_lock);
	ret = sdata->wpan_dev.pan_id;
	spin_unlock_bh(&sdata->mib_lock);

	return ret;
}

void mac802154_dev_set_pan_id(struct net_device *dev, __le16 val)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&sdata->mib_lock);
	sdata->wpan_dev.pan_id = val;
	spin_unlock_bh(&sdata->mib_lock);

	if ((sdata->local->ops->set_hw_addr_filt) &&
	    (sdata->local->hw.hw_filt.pan_id != sdata->wpan_dev.pan_id)) {
		sdata->local->hw.hw_filt.pan_id = sdata->wpan_dev.pan_id;
		set_hw_addr_filt(dev, IEEE802154_AFILT_PANID_CHANGED);
	}
}

u8 mac802154_dev_get_dsn(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	return sdata->dsn++;
}

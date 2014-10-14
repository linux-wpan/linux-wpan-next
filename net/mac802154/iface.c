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
 * Written by:
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Sergey Lapin <slapin@ossfans.org>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/if_arp.h>

#include <net/rtnetlink.h>
#include <linux/nl802154.h>
#include <net/mac802154.h>
#include <net/ieee802154.h>
#include <net/cfg802154.h>

#include "driver-ops.h"
#include "ieee802154_i.h"

static int ieee802154_setup_mac_sublayer(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_local *local = sdata->local;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	int ret;

	if (local->hw.flags & IEEE802154_HW_PROMISCUOUS) {
		ret = drv_set_promiscuous_mode(local,
					       wpan_dev->promiscuous_mode);
		if (ret < 0)
			return ret;
	}

	if (local->hw.flags & IEEE802154_HW_AFILT) {
		ret = drv_set_pan_id(local, wpan_dev->pan_id);
		if (ret < 0)
			return ret;

		ret = drv_set_short_addr(local, wpan_dev->short_addr);
		if (ret < 0)
			return ret;

		ret = drv_set_extended_addr(local, wpan_dev->extended_addr);
		if (ret < 0)
			return ret;

		ret = drv_set_pan_coord(local, wpan_dev_is_coord(wpan_dev));
		if (ret < 0)
			return ret;
	}

	if (local->hw.flags & IEEE802154_HW_CSMA_PARAMS) {
		ret = drv_set_csma_params(local, wpan_dev->min_be,
					  wpan_dev->max_be,
					  wpan_dev->csma_retries);
		if (ret < 0)
			return ret;
	}

	if (local->hw.flags & IEEE802154_HW_FRAME_RETRIES) {
		ret = drv_set_max_frame_retries(local,
						wpan_dev->frame_retries);
		if (ret < 0)
			return ret;
	}

	if (local->hw.flags & IEEE802154_HW_LBT) {
		ret = drv_set_lbt_mode(local, wpan_dev->lbt);
		if (ret < 0)
			return ret;
	}

	return drv_start(local);
}

static int ieee802154_slave_open(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_local *local = sdata->local;
	int ret = 0;

	ASSERT_RTNL();

	switch (sdata->vif.type) {
	case NL802154_IFTYPE_NODE:
	case NL802154_IFTYPE_MONITOR:
	case NL802154_IFTYPE_COORD:
		break;
	case NL802154_IFTYPE_UNSPEC:
	case NUM_NL802154_IFTYPES:
		BUG();
	}

	if (!local->open_count) {
		ret = ieee802154_setup_mac_sublayer(dev);
		if (ret)
			goto err;
	}

	set_bit(SDATA_STATE_RUNNING, &sdata->state);

	local->open_count++;

	netif_start_queue(dev);

	return 0;
err:
	/* might already be clear but that doesn't matter */
	clear_bit(SDATA_STATE_RUNNING, &sdata->state);
	return ret;
}

static int ieee802154_slave_close(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_local *local = sdata->local;

	ASSERT_RTNL();

	netif_stop_queue(dev);

	local->open_count--;

	clear_bit(SDATA_STATE_RUNNING, &sdata->state);

	if (!local->open_count)
		drv_stop(local);

	return 0;
}

static int
ieee802154_wpan_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct sockaddr_ieee802154 *sa =
		(struct sockaddr_ieee802154 *)&ifr->ifr_addr;

	ASSERT_RTNL();

	/* TODO what's about extended? */

	switch (cmd) {
	case SIOCGIFADDR:
		sa->family = AF_IEEE802154;
		sa->addr.mode = IEEE802154_ADDR_SHORT;
		sa->addr.pan_id = le16_to_cpu(wpan_dev->pan_id);
		sa->addr.short_addr = le16_to_cpu(wpan_dev->short_addr);
		break;
	case SIOCSIFADDR:
		if (ieee802154_sdata_running(sdata))
			return -EBUSY;

		dev_warn(&dev->dev,
			 "Using ioctl SIOCSIFADDR isn't recommened!\n");
		if (sa->family != AF_IEEE802154 ||
		    sa->addr.mode != IEEE802154_ADDR_SHORT ||
		    sa->addr.pan_id == IEEE802154_PANID_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_UNDEF)
			return -EINVAL;

		wpan_dev->pan_id = cpu_to_le16(sa->addr.pan_id);
		wpan_dev->short_addr = cpu_to_le16(sa->addr.short_addr);
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static int ieee802154_wpan_mac_addr(struct net_device *dev, void *p)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct net_device *ldev = dev->ieee802154_ptr->lowpan_dev;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	__le64 __le64_extended_addr;
	struct sockaddr *addr = p;

	ASSERT_RTNL();

	/* check if running and if lowpan exist */
	if (ieee802154_sdata_running(sdata))
		return -EBUSY;

	if (wpan_dev_is_monitor(wpan_dev))
		return -EINVAL;

	/* big endian to little */
	__le64_extended_addr = swab64(*((__be64 *)addr->sa_data));

	if (!ieee802154_is_valid_extended_addr(__le64_extended_addr))
		return -EINVAL;

	if (ldev) {
		if (netif_running(ldev))
			return -EBUSY;

		memcpy(ldev->dev_addr, addr->sa_data, dev->addr_len);
	}	

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	wpan_dev->extended_addr = __le64_extended_addr;

	return 0;
}

static int ieee802154_check_concurrent_iface(struct ieee802154_sub_if_data *sdata,
					     enum nl802154_iftype iftype)
{
	struct ieee802154_local *local = sdata->local;
	struct ieee802154_sub_if_data *nsdata;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct wpan_dev *nwpan_dev;

	/* we hold the RTNL here so can safely walk the list */
	list_for_each_entry(nsdata, &local->interfaces, list) {
		if (nsdata != sdata && ieee802154_sdata_running(nsdata)) {
			nwpan_dev = &nsdata->wpan_dev;

			/* check all phy mac sublayer settings are the same.
			 * We have only one phy, different values makes trouble.
			 */

			if (local->hw.flags & IEEE802154_HW_PROMISCUOUS) {
				if (wpan_dev->promiscuous_mode !=
						nwpan_dev->promiscuous_mode)
					return -EBUSY;
			}

			if (local->hw.flags & IEEE802154_HW_AFILT) {
				if (wpan_dev->pan_id != nwpan_dev->pan_id)
					return -EBUSY;

				if (wpan_dev->short_addr != nwpan_dev->short_addr)
					return -EBUSY;

				if (wpan_dev->extended_addr != nwpan_dev->extended_addr)
					return -EBUSY;

				/* hw filter is set to coord functionality,
				 * check on iftypes which are not coords.
				 */
				if (iftype == NL802154_IFTYPE_COORD &&
				    !wpan_dev_is_coord(nwpan_dev))
					return -EBUSY;
			}

			if (local->hw.flags & IEEE802154_HW_CSMA_PARAMS) {
				if (wpan_dev->min_be != nwpan_dev->min_be)
					return -EBUSY;

				if (wpan_dev->max_be != nwpan_dev->max_be)
					return -EBUSY;

				if (wpan_dev->csma_retries != nwpan_dev->csma_retries)
					return -EBUSY;
			}

			if (local->hw.flags & IEEE802154_HW_FRAME_RETRIES) {
				if (wpan_dev->frame_retries != nwpan_dev->frame_retries)
					return -EBUSY;
			}

			if (local->hw.flags & IEEE802154_HW_LBT) {
				if (wpan_dev->lbt != nwpan_dev->lbt)
					return -EBUSY;
			}
		}
	}

	return 0;
}

static int ieee802154_wpan_open(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	int ret;

	ret = ieee802154_check_concurrent_iface(sdata, sdata->vif.type);	
	if (ret < 0)
		return ret;

	return ieee802154_slave_open(dev);
}

/* TODO This function only works for extended address, there is no marker
 * for short address or extended address. Something is wrong here.
 *
 * Need to change that when we support short_addr handling inside of 6LoWPAN.
 */
static int
ieee802154_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	struct ieee802154_hdr *hdr;
	struct ieee802154_addr saddr;
	__be64 __be64_extended_addr;

	hdr = (struct ieee802154_hdr *)skb_mac_header(skb);
	saddr = ieee802154_hdr_saddr(hdr);

	switch (saddr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		/* ndisc use this function and knows extended address
		 * in big endian only.
		 */
		__be64_extended_addr = swab64(saddr.extended_addr);

		memcpy(haddr, &__be64_extended_addr,
		       IEEE802154_ADDR_EXTENDED_LEN);
		return IEEE802154_ADDR_EXTENDED_LEN;
	default:
		return -EADDRNOTAVAIL;
	}
}

static struct header_ops ieee802154_header_ops = {
	.parse		= ieee802154_header_parse,
};

static const struct net_device_ops ieee802154_dataif_ops = {
	.ndo_open		= ieee802154_wpan_open,
	.ndo_stop		= ieee802154_slave_close,
	.ndo_start_xmit		= ieee802154_xmit,
	.ndo_do_ioctl		= ieee802154_wpan_ioctl,
	.ndo_set_mac_address	= ieee802154_wpan_mac_addr,
};

static const struct net_device_ops ieee802154_monitorif_ops = {
	.ndo_open		= ieee802154_wpan_open,
	.ndo_stop		= ieee802154_slave_close,
	.ndo_start_xmit		= ieee802154_monitor_xmit,
};

static void ieee802154_wpan_free(struct net_device *dev)
{
	free_netdev(dev);
}

static void ieee802154_if_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE802154_ADDR_EXTENDED_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_EXTENDED_LEN);

	dev->hard_header_len	= MAC802154_FRAME_HARD_HEADER_LEN;
	dev->header_ops		= &ieee802154_header_ops;
	dev->needed_tailroom	= 2 + 16; /* FCS + MIC */
	dev->mtu		= IEEE802154_MTU;
	dev->tx_queue_len	= 1000;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;

	dev->destructor		= ieee802154_wpan_free;
}

static int ieee802154_setup_sdata(struct ieee802154_sub_if_data *sdata,
				  enum nl802154_iftype type)
{
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;

	/* set some type-dependent values */
	sdata->vif.type = type;
	sdata->wpan_dev.iftype = type;

	/* mac pib defaults here */
	/* defaults per 802.15.4-2011 */
	wpan_dev->extended_addr = swab64(*((__be64 *)sdata->dev->dev_addr));
	wpan_dev->pan_id = cpu_to_le16(IEEE802154_PANID_BROADCAST);
	wpan_dev->short_addr = cpu_to_le16(IEEE802154_ADDR_BROADCAST);

	get_random_bytes(&wpan_dev->bsn, 1);
	get_random_bytes(&wpan_dev->dsn, 1);

	wpan_dev->min_be = 3;
	wpan_dev->max_be = 5;
	wpan_dev->csma_retries = 4;

	wpan_dev->frame_retries = -1;

	switch (type) {
	case NL802154_IFTYPE_COORD:
	case NL802154_IFTYPE_NODE:
		sdata->dev->netdev_ops = &ieee802154_dataif_ops;
		break;
	case NL802154_IFTYPE_MONITOR:
		wpan_dev->promiscuous_mode = true;
		sdata->dev->netdev_ops = &ieee802154_monitorif_ops;
		break;
	case NL802154_IFTYPE_UNSPEC:
	case NUM_NL802154_IFTYPES:
		BUG();
	}

	return 0;
}

int ieee802154_if_add(struct ieee802154_local *local, const char *name,
		      struct wpan_dev **new_wpan_dev, enum nl802154_iftype type)
{
	struct net_device *ndev = NULL;
	struct ieee802154_sub_if_data *sdata = NULL;
	__be64 netdev_addr;
	int ret;

	ASSERT_RTNL();

	ndev = alloc_netdev(sizeof(*sdata) + local->hw.vif_data_size, name,
			    NET_NAME_UNKNOWN, ieee802154_if_setup);
	if (!ndev)
		return -ENOMEM;

	dev_net_set(ndev, wpan_phy_net(local->hw.phy));

	ret = dev_alloc_name(ndev, ndev->name);
	if (ret < 0)
		goto err;

	netdev_addr = swab64(local->hw.phy->perm_extended_addr);
	memcpy(ndev->perm_addr, &netdev_addr, IEEE802154_ADDR_EXTENDED_LEN);
	switch (type) {
	case NL802154_IFTYPE_NODE:
		ndev->type = ARPHRD_IEEE802154;
		memcpy(ndev->dev_addr, ndev->perm_addr, IEEE802154_ADDR_EXTENDED_LEN);
		break;
	case NL802154_IFTYPE_MONITOR:
		ndev->type = ARPHRD_IEEE802154_MONITOR;
		/* monitor should set this to zero */
		memset(ndev->dev_addr, 0, IEEE802154_ADDR_EXTENDED_LEN);
		break;
	case NL802154_IFTYPE_COORD:
		ret = -EOPNOTSUPP;
		goto err;
	case NL802154_IFTYPE_UNSPEC:
	case NUM_NL802154_IFTYPES:
		BUG();
	}

	SET_NETDEV_DEV(ndev, wpan_phy_dev(local->hw.phy));
	sdata = netdev_priv(ndev);
	ndev->ieee802154_ptr = &sdata->wpan_dev;
	memcpy(sdata->name, ndev->name, IFNAMSIZ);
	sdata->dev = ndev;
	sdata->wpan_dev.wpan_phy = local->hw.phy;
	sdata->local = local;

	/* setup type-dependent data */
	ret = ieee802154_setup_sdata(sdata, type);
	if (ret)
		goto err;

	if (ndev) {
		ret = register_netdevice(ndev);
		if (ret)
			goto err;
	}

	mutex_lock(&local->iflist_mtx);
	list_add_tail_rcu(&sdata->list, &local->interfaces);
	mutex_unlock(&local->iflist_mtx);

	if (new_wpan_dev)
		*new_wpan_dev = &sdata->wpan_dev;

	return 0;

err:
	free_netdev(ndev);
	return ret;
}

void ieee802154_if_remove(struct ieee802154_sub_if_data *sdata)
{
	ASSERT_RTNL();

	mutex_lock(&sdata->local->iflist_mtx);
	list_del_rcu(&sdata->list);
	mutex_unlock(&sdata->local->iflist_mtx);

	synchronize_rcu();

	if (sdata->dev) {
		unregister_netdevice(sdata->dev);
	} else {
		cfg802154_unregister_wpan_dev(&sdata->wpan_dev);
		kfree(sdata);
	}
}

/*
 * Remove all interfaces, may only be called at hardware unregistration
 * time because it doesn't do RCU-safe list removals.
 */
void ieee802154_remove_interfaces(struct ieee802154_local *local)
{
	struct ieee802154_sub_if_data *sdata, *tmp;
	LIST_HEAD(unreg_list);
	LIST_HEAD(wpan_dev_list);

	ASSERT_RTNL();

	/*
	 * Close all AP_VLAN interfaces first, as otherwise they
	 * might be closed while the AP interface they belong to
	 * is closed, causing unregister_netdevice_many() to crash.
	 */
	list_for_each_entry(sdata, &local->interfaces, list)
	mutex_lock(&local->iflist_mtx);
	list_for_each_entry_safe(sdata, tmp, &local->interfaces, list) {
		list_del(&sdata->list);

		if (sdata->dev)
			unregister_netdevice_queue(sdata->dev, &unreg_list);
		else
			list_add(&sdata->list, &wpan_dev_list);
	}
	mutex_unlock(&local->iflist_mtx);
	unregister_netdevice_many(&unreg_list);

	list_for_each_entry_safe(sdata, tmp, &wpan_dev_list, list) {
		list_del(&sdata->list);
		cfg802154_unregister_wpan_dev(&sdata->wpan_dev);
		kfree(sdata);
	}
}

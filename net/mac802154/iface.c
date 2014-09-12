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
#include <net/af_ieee802154.h>
#include <net/mac802154.h>
#include <net/ieee802154_netdev.h>
#include <net/ieee802154.h>
#include <net/cfg802154.h>

#include "driver-ops.h"
#include "ieee802154_i.h"

static int ieee802154_slave_open(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_local *local = sdata->local;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	int ret = 0;

	ASSERT_RTNL();

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

		ret = drv_set_pan_coord(local, sdata->vif.type ==
					       NL802154_IFTYPE_COORD);
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

	if (local->hw.flags & IEEE802154_HW_PROMISCOUS) {
		ret = drv_set_promiscous_mode(local, sdata->vif.type ==
						     NL802154_IFTYPE_MONITOR);
		if (ret < 0)
			return ret;
	}

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
		ret = drv_start(local);
		WARN_ON(ret);
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
		sa->addr.addr_type = IEEE802154_ADDR_SHORT;
		sa->addr.pan_id = le16_to_cpu(wpan_dev->pan_id);
		sa->addr.short_addr = le16_to_cpu(wpan_dev->short_addr);
		break;
	case SIOCSIFADDR:
		if (ieee802154_sdata_running(sdata))
			return -EBUSY;

		dev_warn(&dev->dev,
			 "Using ioctl SIOCSIFADDR isn't recommened!\n");
		if (sa->family != AF_IEEE802154 ||
		    sa->addr.addr_type != IEEE802154_ADDR_SHORT ||
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
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	__le64 __le64_extended_addr;
	struct sockaddr *addr = p;
	int ret;

	ASSERT_RTNL();

	if (ieee802154_sdata_running(sdata))
		return -EBUSY;

	/* big endian to little */
	__le64_extended_addr = swab64(*((__be64 *)addr->sa_data));

	if (ieee802154_is_valid_extended_addr(__le64_extended_addr))
		return -EINVAL;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	wpan_dev->extended_addr = __le64_extended_addr;

	return 0;
}

static int ieee802154_check_concurrent_iface(struct ieee802154_sub_if_data *sdata,
					     enum nl802154_iftype iftype)
{
	struct ieee802154_local *local = sdata->local;
	struct ieee802154_sub_if_data *nsdata;

	/* we hold the RTNL here so can safely walk the list */
	 list_for_each_entry(nsdata, &local->interfaces, list) {
		 if (nsdata != sdata && ieee802154_sdata_running(nsdata)) {
			 /* don't allow multiple NODE interfaces */
			 if (iftype == NL802154_IFTYPE_NODE &&
			     nsdata->vif.type == NL802154_IFTYPE_NODE)
				 return -EBUSY;
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

static int ieee802154_header_create(struct sk_buff *skb,
				   struct net_device *dev,
				   unsigned short type,
				   const void *daddr,
				   const void *saddr,
				   unsigned len)
{
	struct ieee802154_hdr hdr;
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	struct ieee802154_mac_cb *cb = mac_cb(skb);
	int hlen;

	if (!daddr)
		return -EINVAL;

	memset(&hdr.fc, 0, sizeof(hdr.fc));
	hdr.fc.type = cb->type;
	hdr.fc.security_enabled = cb->secen;
	hdr.fc.ack_request = cb->ackreq;
	hdr.seq = wpan_dev->dsn++;

	if (!saddr) {
		if (wpan_dev->short_addr ==
		    cpu_to_le16(IEEE802154_ADDR_BROADCAST) ||
		    wpan_dev->short_addr == cpu_to_le16(IEEE802154_ADDR_UNDEF) ||
		    wpan_dev->pan_id == cpu_to_le16(IEEE802154_PANID_BROADCAST)) {
			hdr.source.mode = IEEE802154_ADDR_LONG;
			hdr.source.extended_addr = wpan_dev->extended_addr;
		} else {
			hdr.source.mode = IEEE802154_ADDR_SHORT;
			hdr.source.short_addr = wpan_dev->short_addr;
		}

		hdr.source.pan_id = wpan_dev->pan_id;
	} else {
		hdr.source = *(const struct ieee802154_addr *)saddr;
	}

	hdr.dest = *(const struct ieee802154_addr *)daddr;

	hlen = ieee802154_hdr_push(skb, &hdr);
	if (hlen < 0)
		return -EINVAL;

	skb_reset_mac_header(skb);
	skb->mac_len = hlen;

	if (len > ieee802154_max_payload(&hdr))
		return -EMSGSIZE;

	return hlen;
}

static int
ieee802154_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	struct ieee802154_hdr hdr;
	struct ieee802154_addr *addr = (struct ieee802154_addr *)haddr;

	if (ieee802154_hdr_peek_addrs(skb, &hdr) < 0) {
		pr_debug("malformed packet\n");
		return 0;
	}

	*addr = hdr.source;
	return sizeof(*addr);
}

static struct header_ops ieee802154_header_ops = {
	.create		= ieee802154_header_create,
	.parse		= ieee802154_header_parse,
};

static const struct net_device_ops ieee802154_wpan_ops = {
	.ndo_open		= ieee802154_wpan_open,
	.ndo_stop		= ieee802154_slave_close,
	.ndo_start_xmit		= ieee802154_xmit,
	.ndo_do_ioctl		= ieee802154_wpan_ioctl,
	.ndo_set_mac_address	= ieee802154_wpan_mac_addr,
};

static void ieee802154_wpan_free(struct net_device *dev)
{
	free_netdev(dev);
}

static void ieee802154_if_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE802154_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_LEN);

	dev->hard_header_len	= MAC802154_FRAME_HARD_HEADER_LEN;
	dev->header_ops		= &ieee802154_header_ops;
	dev->needed_tailroom	= 2 + 16; /* FCS + MIC */
	dev->mtu		= IEEE802154_MTU;
	dev->tx_queue_len	= 1000;
	dev->type		= ARPHRD_IEEE802154;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;

	dev->destructor		= ieee802154_wpan_free;
	dev->netdev_ops		= &ieee802154_wpan_ops;
}

static int ieee802154_setup_sdata(struct ieee802154_sub_if_data *sdata,
				  enum nl802154_iftype type)
{
	struct ieee802154_local *local = sdata->local;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;

	/* set some type-dependent values */
	sdata->vif.type = type;
	sdata->wpan_dev.iftype = type;

	/* mac pib defaults here */
	/* defaults per 802.15.4-2011 */
	wpan_dev->extended_addr = local->hw.phy->perm_extended_addr;
	wpan_dev->pan_id = cpu_to_le16(IEEE802154_PANID_BROADCAST);
	wpan_dev->short_addr = cpu_to_le16(IEEE802154_ADDR_BROADCAST);

	get_random_bytes(&wpan_dev->bsn, 1);
	get_random_bytes(&wpan_dev->dsn, 1);

	wpan_dev->min_be = 3;
	wpan_dev->max_be = 5;
	wpan_dev->csma_retries = 4;

	wpan_dev->frame_retries = 3;

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

	switch (type) {
	case NL802154_IFTYPE_NODE:
	case NL802154_IFTYPE_MONITOR:
		break;
	case NL802154_IFTYPE_COORD:
		ret = -EOPNOTSUPP;
		goto err;
	case NL802154_IFTYPE_UNSPEC:
	case NUM_NL802154_IFTYPES:
		BUG();
	}

	netdev_addr = swab64(local->hw.phy->perm_extended_addr);
	memcpy(ndev->perm_addr, &netdev_addr, IEEE802154_ADDR_LEN);
	memcpy(ndev->dev_addr, ndev->perm_addr, IEEE802154_ADDR_LEN);
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

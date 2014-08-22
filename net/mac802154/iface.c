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

static int mac802154_slave_open(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_sub_if_data *subif;
	struct ieee802154_local *local = sdata->local;
	int res = 0;

	ASSERT_RTNL();

	switch (sdata->vif.type) {
	case NL802154_IFTYPE_NODE:
		mutex_lock(&sdata->local->iflist_mtx);
		list_for_each_entry(subif, &sdata->local->interfaces, list) {
			if (subif != sdata &&
			    subif->vif.type == sdata->vif.type &&
			    ieee802154_sdata_running(subif)) {
				mutex_unlock(&sdata->local->iflist_mtx);
				return -EBUSY;
			}
		}
		mutex_unlock(&sdata->local->iflist_mtx);
		break;
	case NL802154_IFTYPE_MONITOR:
	case NL802154_IFTYPE_COORD:
		break;
	case NL802154_IFTYPE_UNSPEC:
	case NUM_NL802154_IFTYPES:
		BUG();
	}

	if (!local->open_count) {
		res = drv_start(local);
		WARN_ON(res);
		if (res)
			goto err;
	}

	set_bit(SDATA_STATE_RUNNING, &sdata->state);

	local->open_count++;

	netif_start_queue(dev);

	return 0;
err:
	/* might already be clear but that doesn't matter */
	clear_bit(SDATA_STATE_RUNNING, &sdata->state);
	return res;
}

static int mac802154_slave_close(struct net_device *dev)
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

static int mac802154_wpan_update_llsec(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_mlme_ops *ops = ieee802154_mlme_ops(dev);
	int rc = 0;

	if (ops->llsec) {
		struct ieee802154_llsec_params params;
		int changed = 0;

		params.pan_id = sdata->wpan_dev.pan_id;
		changed |= IEEE802154_LLSEC_PARAM_PAN_ID;

		params.hwaddr = sdata->extended_addr;
		changed |= IEEE802154_LLSEC_PARAM_HWADDR;

		rc = ops->llsec->set_params(dev, &params, changed);
	}

	return rc;
}

static int
mac802154_wpan_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct sockaddr_ieee802154 *sa =
		(struct sockaddr_ieee802154 *)&ifr->ifr_addr;
	int err = -ENOIOCTLCMD;

	spin_lock_bh(&sdata->mib_lock);

	switch (cmd) {
	case SIOCGIFADDR:
	{
		u16 pan_id, short_addr;

		pan_id = le16_to_cpu(sdata->wpan_dev.pan_id);
		short_addr = le16_to_cpu(sdata->short_addr);
		if (pan_id == IEEE802154_PANID_BROADCAST ||
		    short_addr == IEEE802154_ADDR_BROADCAST) {
			err = -EADDRNOTAVAIL;
			break;
		}

		sa->family = AF_IEEE802154;
		sa->addr.addr_type = IEEE802154_ADDR_SHORT;
		sa->addr.pan_id = pan_id;
		sa->addr.short_addr = short_addr;

		err = 0;
		break;
	}
	case SIOCSIFADDR:
		dev_warn(&dev->dev,
			 "Using DEBUGing ioctl SIOCSIFADDR isn't recommened!\n");
		if (sa->family != AF_IEEE802154 ||
		    sa->addr.addr_type != IEEE802154_ADDR_SHORT ||
		    sa->addr.pan_id == IEEE802154_PANID_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_BROADCAST ||
		    sa->addr.short_addr == IEEE802154_ADDR_UNDEF) {
			err = -EINVAL;
			break;
		}

		sdata->wpan_dev.pan_id = cpu_to_le16(sa->addr.pan_id);
		sdata->short_addr = cpu_to_le16(sa->addr.short_addr);

		err = mac802154_wpan_update_llsec(dev);
		break;
	}

	spin_unlock_bh(&sdata->mib_lock);
	return err;
}

static int mac802154_wpan_mac_addr(struct net_device *dev, void *p)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct sockaddr *addr = p;
	int ret;

	ASSERT_RTNL();

	if (netif_running(dev))
		return -EBUSY;

	/* FIXME: validate addr */
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	sdata->extended_addr = ieee802154_devaddr_from_raw(dev->dev_addr);
	if (sdata->local->hw.flags & IEEE802154_HW_AFILT) {
		ret = drv_set_extended_addr(sdata->local,
					    sdata->extended_addr);
		if (ret < 0)
			return ret;
	}

	return mac802154_wpan_update_llsec(dev);
}

static int mac802154_wpan_open(struct net_device *dev)
{
	int rc;

	rc = mac802154_slave_open(dev);
	if (rc < 0)
		return rc;

	return 0;
}

static int mac802154_set_header_security(struct ieee802154_sub_if_data *sdata,
					 struct ieee802154_hdr *hdr,
					 const struct ieee802154_mac_cb *cb)
{
	struct ieee802154_llsec_params params;
	u8 level;

	mac802154_llsec_get_params(&sdata->sec, &params);

	if (!params.enabled && cb->secen_override && cb->secen)
		return -EINVAL;
	if (!params.enabled ||
	    (cb->secen_override && !cb->secen) ||
	    !params.out_level)
		return 0;
	if (cb->seclevel_override && !cb->seclevel)
		return -EINVAL;

	level = cb->seclevel_override ? cb->seclevel : params.out_level;

	hdr->fc.security_enabled = 1;
	hdr->sec.level = level;
	hdr->sec.key_id_mode = params.out_key.mode;
	if (params.out_key.mode == IEEE802154_SCF_KEY_SHORT_INDEX)
		hdr->sec.short_src = params.out_key.short_source;
	else if (params.out_key.mode == IEEE802154_SCF_KEY_HW_INDEX)
		hdr->sec.extended_src = params.out_key.extended_source;
	hdr->sec.key_id = params.out_key.id;

	return 0;
}

static int mac802154_header_create(struct sk_buff *skb,
				   struct net_device *dev,
				   unsigned short type,
				   const void *daddr,
				   const void *saddr,
				   unsigned len)
{
	struct ieee802154_hdr hdr;
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	struct ieee802154_mac_cb *cb = mac_cb(skb);
	int hlen;

	if (!daddr)
		return -EINVAL;

	memset(&hdr.fc, 0, sizeof(hdr.fc));
	hdr.fc.type = cb->type;
	hdr.fc.security_enabled = cb->secen;
	hdr.fc.ack_request = cb->ackreq;
	hdr.seq = ieee802154_mlme_ops(dev)->get_dsn(dev);

	if (mac802154_set_header_security(sdata, &hdr, cb) < 0)
		return -EINVAL;

	if (!saddr) {
		spin_lock_bh(&sdata->mib_lock);

		if (sdata->short_addr ==
		    cpu_to_le16(IEEE802154_ADDR_BROADCAST) ||
		    sdata->short_addr == cpu_to_le16(IEEE802154_ADDR_UNDEF) ||
		    sdata->wpan_dev.pan_id == cpu_to_le16(IEEE802154_PANID_BROADCAST)) {
			hdr.source.mode = IEEE802154_ADDR_LONG;
			hdr.source.extended_addr = sdata->extended_addr;
		} else {
			hdr.source.mode = IEEE802154_ADDR_SHORT;
			hdr.source.short_addr = sdata->short_addr;
		}

		hdr.source.pan_id = sdata->wpan_dev.pan_id;

		spin_unlock_bh(&sdata->mib_lock);
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
mac802154_header_parse(const struct sk_buff *skb, unsigned char *haddr)
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

static struct header_ops mac802154_header_ops = {
	.create		= mac802154_header_create,
	.parse		= mac802154_header_parse,
};

static const struct net_device_ops mac802154_wpan_ops = {
	.ndo_open		= mac802154_wpan_open,
	.ndo_stop		= mac802154_slave_close,
	.ndo_start_xmit		= mac802154_wpan_xmit,
	.ndo_do_ioctl		= mac802154_wpan_ioctl,
	.ndo_set_mac_address	= mac802154_wpan_mac_addr,
};

static void mac802154_wpan_free(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	mac802154_llsec_destroy(&sdata->sec);

	free_netdev(dev);
}

static void ieee802154_if_setup(struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata;

	dev->addr_len		= IEEE802154_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_LEN);

	dev->hard_header_len	= MAC802154_FRAME_HARD_HEADER_LEN;
	dev->header_ops		= &mac802154_header_ops;
	dev->needed_tailroom	= 2 + 16; /* FCS + MIC */
	dev->mtu		= IEEE802154_MTU;
	dev->tx_queue_len	= 300;
	dev->type		= ARPHRD_IEEE802154;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;

	dev->destructor		= mac802154_wpan_free;
	dev->netdev_ops		= &mac802154_wpan_ops;
	dev->ml_priv		= &mac802154_mlme_wpan;

	sdata = IEEE802154_DEV_TO_SUB_IF(dev);
	sdata->vif.type = NL802154_IFTYPE_NODE;

	spin_lock_init(&sdata->mib_lock);
	mutex_init(&sdata->sec_mtx);

	get_random_bytes(&sdata->bsn, 1);
	get_random_bytes(&sdata->dsn, 1);

	sdata->wpan_dev.pan_id = cpu_to_le16(IEEE802154_PANID_BROADCAST);
	sdata->short_addr = cpu_to_le16(IEEE802154_ADDR_BROADCAST);

	mac802154_llsec_init(&sdata->sec);
}

static int ieee802154_setup_sdata(struct ieee802154_sub_if_data *sdata,
				  enum nl802154_iftype type)
{
	struct ieee802154_local *local = sdata->local;
	struct wpan_dev *wpan_dev = &sdata->wpan_dev;
	int ret;

	/* set some type-dependent values */
	sdata->vif.type = type;
	sdata->wpan_dev.iftype = type;

	/* mac pib defaults here */
	/* defaults per 802.15.4-2011 */
	sdata->extended_addr = local->hw.phy->perm_extended_addr;
	if (local->hw.flags & IEEE802154_HW_AFILT) {
		ret = drv_set_extended_addr(local, sdata->extended_addr);
		if (ret < 0)
			return ret;
	}

	wpan_dev->min_be = 3;
	wpan_dev->max_be = 5;
	wpan_dev->csma_retries = 4;
	if (local->hw.flags & IEEE802154_HW_CSMA_PARAMS) {
		ret = drv_set_csma_params(local, wpan_dev->min_be,
					  wpan_dev->max_be,
					  wpan_dev->csma_retries);
		if (ret < 0)
			return ret;
	}
	/* for compatibility, actual default is 3 */
	wpan_dev->frame_retries = -1;


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
		break;
	case NL802154_IFTYPE_MONITOR:
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

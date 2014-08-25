/* Copyright 2011, Siemens AG
 * written by Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

/* Based on patches from Jon Smirl <jonsmirl@gmail.com>
 * Copyright (c) 2011 Jon Smirl <jonsmirl@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* Jon's code is based on 6lowpan implementation for Contiki which is:
 * Copyright (c) 2008, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <linux/bitops.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>

#include <net/af_ieee802154.h>
#include <net/ieee802154.h>
#include <net/cfg802154.h>
#include <net/ieee802154_netdev.h>
#include <net/6lowpan.h>
#include <net/ipv6.h>

#include "6lowpan_i.h"
#include "reassembly.h"

static int lowpan_set_address(struct net_device *ldev, void *p)
{
	struct sockaddr *sa = p;

	if (netif_running(ldev))
		return -EBUSY;

	/* TODO: validate addr */
	memcpy(ldev->dev_addr, sa->sa_data, ldev->addr_len);

	return 0;
}

static struct wpan_phy *lowpan_get_phy(const struct net_device *ldev)
{
	struct net_device *wdev = lowpan_dev_info(ldev)->wdev;

	return ieee802154_mlme_ops(wdev)->get_phy(wdev);
}

static __le16 lowpan_get_pan_id(const struct net_device *ldev)
{
	struct net_device *wdev = lowpan_dev_info(ldev)->wdev;

	return ieee802154_mlme_ops(wdev)->get_pan_id(wdev);
}

static __le16 lowpan_get_short_addr(const struct net_device *ldev)
{
	struct net_device *wdev = lowpan_dev_info(ldev)->wdev;

	return ieee802154_mlme_ops(wdev)->get_short_addr(wdev);
}

static u8 lowpan_get_dsn(const struct net_device *ldev)
{
	struct net_device *wdev = lowpan_dev_info(ldev)->wdev;

	return ieee802154_mlme_ops(wdev)->get_dsn(wdev);
}

static struct header_ops lowpan_header_ops = {
	.create	= lowpan_header_create,
};

static struct lock_class_key lowpan_tx_busylock;
static struct lock_class_key lowpan_netdev_xmit_lock_key;

static void lowpan_set_lockdep_class_one(struct net_device *ldev,
					 struct netdev_queue *txq,
					 void *_unused)
{
	lockdep_set_class(&txq->_xmit_lock,
			  &lowpan_netdev_xmit_lock_key);
}


static int lowpan_dev_init(struct net_device *ldev)
{
	netdev_for_each_tx_queue(ldev, lowpan_set_lockdep_class_one, NULL);
	ldev->qdisc_tx_busylock = &lowpan_tx_busylock;
	return 0;
}

static const struct net_device_ops lowpan_netdev_ops = {
	.ndo_init		= lowpan_dev_init,
	.ndo_start_xmit		= lowpan_xmit,
	.ndo_set_mac_address	= lowpan_set_address,
};

static struct ieee802154_mlme_ops lowpan_mlme = {
	.get_pan_id = lowpan_get_pan_id,
	.get_phy = lowpan_get_phy,
	.get_short_addr = lowpan_get_short_addr,
	.get_dsn = lowpan_get_dsn,
};

static void lowpan_setup(struct net_device *ldev)
{
	ldev->addr_len		= IEEE802154_ADDR_LEN;
	memset(ldev->broadcast, 0xff, IEEE802154_ADDR_LEN);
	ldev->type		= ARPHRD_IEEE802154;
	/* Frame Control + Sequence Number + Address fields + Security Header */
	ldev->hard_header_len	= 2 + 1 + 20 + 14;
	ldev->needed_tailroom	= 2; /* FCS */
	ldev->mtu		= 1281;
	ldev->tx_queue_len	= 0;
	ldev->flags		= IFF_BROADCAST | IFF_MULTICAST;
	ldev->watchdog_timeo	= 0;

	ldev->netdev_ops	= &lowpan_netdev_ops;
	ldev->header_ops	= &lowpan_header_ops;
	ldev->ml_priv		= &lowpan_mlme;
	ldev->destructor	= free_netdev;
}

static int lowpan_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != IEEE802154_ADDR_LEN)
			return -EINVAL;
	}
	return 0;
}

static int lowpan_newlink(struct net *src_net, struct net_device *ldev,
			  struct nlattr *tb[], struct nlattr *data[])
{
	struct net_device *wdev;

	pr_debug("adding new link\n");

	if (!tb[IFLA_LINK])
		return -EINVAL;
	/* find and hold real wpan device */
	wdev = dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));
	if (!wdev)
		return -ENODEV;
	if (wdev->type != ARPHRD_IEEE802154) {
		dev_put(wdev);
		return -EINVAL;
	}

	if (wdev->ieee802154_ptr->lowpan_dev) {
		dev_put(wdev);
		return -EBUSY;
	}

	wdev->ieee802154_ptr->lowpan_dev = ldev;
	lowpan_dev_info(ldev)->wdev = wdev;

	/* Set the lowpan harware address to the wpan hardware address. */
	memcpy(ldev->dev_addr, wdev->dev_addr, IEEE802154_ADDR_LEN);

	return register_netdevice(ldev);
}

static void lowpan_dellink(struct net_device *ldev, struct list_head *head)
{
	struct lowpan_dev_info *lowpan_dev = lowpan_dev_info(ldev);
	struct net_device *wdev = lowpan_dev->wdev;

	ASSERT_RTNL();

	unregister_netdevice_queue(ldev, head);
	dev_put(wdev);
}

static struct rtnl_link_ops lowpan_link_ops __read_mostly = {
	.kind		= "lowpan",
	.priv_size	= sizeof(struct lowpan_dev_info),
	.setup		= lowpan_setup,
	.newlink	= lowpan_newlink,
	.dellink	= lowpan_dellink,
	.validate	= lowpan_validate,
};

static inline int __init lowpan_netlink_init(void)
{
	return rtnl_link_register(&lowpan_link_ops);
}

static inline void lowpan_netlink_fini(void)
{
	rtnl_link_unregister(&lowpan_link_ops);
}

static int __init lowpan_init_module(void)
{
	int err = 0;

	err = lowpan_net_frag_init();
	if (err < 0)
		goto out;

	err = lowpan_netlink_init();
	if (err < 0)
		goto out_frag;

	lowpan_init_rx();

	return 0;

out_frag:
	lowpan_net_frag_exit();
out:
	return err;
}

static void __exit lowpan_cleanup_module(void)
{
	lowpan_netlink_fini();

	lowpan_cleanup_rx();

	lowpan_net_frag_exit();
}

module_init(lowpan_init_module);
module_exit(lowpan_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("lowpan");

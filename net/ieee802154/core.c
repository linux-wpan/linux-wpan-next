/*
 * Copyright (C) 2007, 2008, 2009 Siemens AG
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
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>

#include <net/cfg802154.h>
#include <net/mac802154.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

#include "nl802154.h"
#include "core.h"
#include "sysfs.h"
#include "rdev-ops.h"

#define PHY_NAME "phy"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Dmitry Eremin-Solenikov");
MODULE_DESCRIPTION("IEEE 802.15.4 configuration interface");
MODULE_ALIAS_GENL_FAMILY(NL802154_GENL_NAME);

/* RCU-protected (and RTNL for writers) */
LIST_HEAD(cfg802154_rdev_list);
int cfg802154_rdev_list_generation;

struct cfg802154_registered_device *
cfg802154_rdev_by_wpan_phy_idx(int wpan_phy_idx)
{
	struct cfg802154_registered_device *result = NULL, *rdev;

	ASSERT_RTNL();

	list_for_each_entry(rdev, &cfg802154_rdev_list, list) {
		if (rdev->wpan_phy_idx == wpan_phy_idx) {
			result = rdev;
			break;
		}
	}

	return result;
}

int cfg802154_switch_netns(struct cfg802154_registered_device *rdev,
			   struct net *net)
{
	struct wpan_dev *wpan_dev;
	int err = 0;

	if (!(rdev->wpan_phy.flags & WPAN_PHY_FLAG_NETNS_OK))
		return -EOPNOTSUPP;

	list_for_each_entry(wpan_dev, &rdev->wpan_dev_list, list) {
		if (!wpan_dev->netdev)
			continue;
		wpan_dev->netdev->features &= ~NETIF_F_NETNS_LOCAL;
		err = dev_change_net_namespace(wpan_dev->netdev, net, "wpan%d");
		if (err)
			break;
		wpan_dev->netdev->features |= NETIF_F_NETNS_LOCAL;
	}

	if (err) {
		/* failed -- clean up to old netns */
		net = wpan_phy_net(&rdev->wpan_phy);

		list_for_each_entry_continue_reverse(wpan_dev,
						     &rdev->wpan_dev_list,
						     list) {
			if (!wpan_dev->netdev)
				continue;
			wpan_dev->netdev->features &= ~NETIF_F_NETNS_LOCAL;
			err = dev_change_net_namespace(wpan_dev->netdev, net,
							"wpan%d");
			WARN_ON(err);
			wpan_dev->netdev->features |= NETIF_F_NETNS_LOCAL;
		}

		return err;
	}

	wpan_phy_net_set(&rdev->wpan_phy, net);

	err = device_rename(&rdev->wpan_phy.dev, dev_name(&rdev->wpan_phy.dev));
	WARN_ON(err);

	return 0;
}

void cfg802154_destroy_ifaces(struct cfg802154_registered_device *rdev)
{
	struct cfg802154_iface_destroy *item;

	ASSERT_RTNL();

	spin_lock_irq(&rdev->destroy_list_lock);
	while ((item = list_first_entry_or_null(&rdev->destroy_list,
						struct cfg802154_iface_destroy,
						list))) {
		struct wpan_dev *wpan_dev, *tmp;
		u32 nlportid = item->nlportid;

		list_del(&item->list);
		kfree(item);
		spin_unlock_irq(&rdev->destroy_list_lock);

		list_for_each_entry_safe(wpan_dev, tmp, &rdev->wpan_dev_list, list) {
			if (nlportid == wpan_dev->owner_nlportid)
				rdev_del_virtual_intf(rdev, wpan_dev);
		}

		spin_lock_irq(&rdev->destroy_list_lock);
	}
	spin_unlock_irq(&rdev->destroy_list_lock);
}

static void cfg802154_destroy_iface_wk(struct work_struct *work)
{
	struct cfg802154_registered_device *rdev;

	rdev = container_of(work, struct cfg802154_registered_device,
			    destroy_work);

	rtnl_lock();
	cfg802154_destroy_ifaces(rdev);
	rtnl_unlock();
}

/* exported functions */

struct wpan_phy *wpan_phy_new(const struct cfg802154_ops *ops,
			      size_t sizeof_priv)
{
	static atomic_t wpan_phy_counter = ATOMIC_INIT(0);
	struct cfg802154_registered_device *rdev;
	size_t alloc_size;

	WARN_ON(ops->add_virtual_intf && !ops->del_virtual_intf);

	alloc_size = sizeof(*rdev) + sizeof_priv;
	rdev = kzalloc(alloc_size, GFP_KERNEL);
	if (!rdev)
		return NULL;

	rdev->ops = ops;

	rdev->wpan_phy_idx = atomic_inc_return(&wpan_phy_counter);

	if (unlikely(rdev->wpan_phy_idx < 0)) {
		/* ugh, wrapped! */
		atomic_dec(&wpan_phy_counter);
		kfree(rdev);
		return NULL;
	}

	/* atomic_inc_return makes it start at 1, make it start at 0 */
	rdev->wpan_phy_idx--;

	/* give it a proper name */
	dev_set_name(&rdev->wpan_phy.dev, PHY_NAME "%d", rdev->wpan_phy_idx);

	INIT_LIST_HEAD(&rdev->wpan_dev_list);
	device_initialize(&rdev->wpan_phy.dev);
	rdev->wpan_phy.dev.class = &ieee802154_class;
	rdev->wpan_phy.dev.platform_data = rdev;

	INIT_LIST_HEAD(&rdev->destroy_list);
	spin_lock_init(&rdev->destroy_list_lock);
	INIT_WORK(&rdev->destroy_work, cfg802154_destroy_iface_wk);

	wpan_phy_net_set(&rdev->wpan_phy, &init_net);

	init_waitqueue_head(&rdev->dev_wait);

	return &rdev->wpan_phy;
}
EXPORT_SYMBOL(wpan_phy_new);

int wpan_phy_register(struct wpan_phy *wpan_phy)
{
	struct cfg802154_registered_device *rdev = wpan_phy_to_rdev(wpan_phy);
	int res;

	rtnl_lock();
	res = device_add(&rdev->wpan_phy.dev);
	if (res) {
		rtnl_unlock();
		return res;
	}

	list_add_rcu(&rdev->list, &cfg802154_rdev_list);
	cfg802154_rdev_list_generation++;

	rdev->wpan_phy.registered = true;
	rtnl_unlock();

	nl802154_notify_wpan_phy(rdev, NL802154_CMD_NEW_WPAN_PHY);

	return 0;
}
EXPORT_SYMBOL(wpan_phy_register);

void wpan_phy_unregister(struct wpan_phy *wpan_phy)
{
	struct cfg802154_registered_device *rdev = wpan_phy_to_rdev(wpan_phy);

	wait_event(rdev->dev_wait, ({
		int __count;
		rtnl_lock();
		__count = rdev->opencount;
		rtnl_unlock();
		__count == 0; }));

	rtnl_lock();
	nl802154_notify_wpan_phy(rdev, NL802154_CMD_DEL_WPAN_PHY);
	rdev->wpan_phy.registered = false;

	WARN_ON(!list_empty(&rdev->wpan_dev_list));

	/*
	 * First remove the hardware from everywhere, this makes
	 * it impossible to find from userspace.
	 */
	list_del_rcu(&rdev->list);
	synchronize_rcu();

	cfg802154_rdev_list_generation++;
	device_del(&rdev->wpan_phy.dev);

	rtnl_unlock();

	flush_work(&rdev->destroy_work);
}
EXPORT_SYMBOL(wpan_phy_unregister);

void wpan_phy_free(struct wpan_phy *phy)
{
	put_device(&phy->dev);
}
EXPORT_SYMBOL(wpan_phy_free);

void cfg802154_dev_free(struct cfg802154_registered_device *rdev)
{
        kfree(rdev);
}

void cfg802154_unregister_wpan_dev(struct wpan_dev *wpan_dev)
{
	struct cfg802154_registered_device *rdev = wpan_phy_to_rdev(wpan_dev->wpan_phy);

	ASSERT_RTNL();

	if (WARN_ON(wpan_dev->netdev))
		return;

	list_del_rcu(&wpan_dev->list);
	rdev->devlist_generation++;
}
EXPORT_SYMBOL(cfg802154_unregister_wpan_dev);

static const struct device_type wpan_phy_type = {
	.name	= "wpan",
};

void cfg802154_update_iface_num(struct cfg802154_registered_device *rdev,
				enum nl802154_iftype iftype, int num)
{
	ASSERT_RTNL();

	rdev->num_running_ifaces += num;
}

static int cfg802154_netdev_notifier_call(struct notifier_block *nb,
					  unsigned long state, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;
	struct cfg802154_registered_device *rdev;

	if (!wpan_dev)
		return NOTIFY_DONE;

	rdev = wpan_phy_to_rdev(wpan_dev->wpan_phy);

	WARN_ON(wpan_dev->iftype == NL802154_IFTYPE_UNSPEC);

	switch (state) {
	case NETDEV_POST_INIT:
		SET_NETDEV_DEVTYPE(dev, &wpan_phy_type);
		break;
	case NETDEV_REGISTER:
		list_add_rcu(&wpan_dev->list, &rdev->wpan_dev_list);
		rdev->devlist_generation++;

		wpan_dev->netdev = dev;
		break;
	case NETDEV_DOWN:
		cfg802154_update_iface_num(rdev, wpan_dev->iftype, -1);

		rdev->opencount--;
		wake_up(&rdev->dev_wait);
		break;
	case NETDEV_UP:
		cfg802154_update_iface_num(rdev, wpan_dev->iftype, 1);

		rdev->opencount++;
		break;
	case NETDEV_UNREGISTER:
		/*
		 * It is possible to get NETDEV_UNREGISTER
		 * multiple times. To detect that, check
		 * that the interface is still on the list
		 * of registered interfaces, and only then
		 * remove and clean it up.
		 */
		if (!list_empty(&wpan_dev->list)) {
			list_del_rcu(&wpan_dev->list);
			rdev->devlist_generation++;
		}
		/*
		 * synchronize (so that we won't find this netdev
		 * from other code any more) and then clear the list
		 * head so that the above code can safely check for
		 * !list_empty() to avoid double-cleanup.
		 */
		synchronize_rcu();
		INIT_LIST_HEAD(&wpan_dev->list);
		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}

static struct notifier_block cfg802154_netdev_notifier = {
	.notifier_call = cfg802154_netdev_notifier_call,
};

static void __net_exit cfg802154_pernet_exit(struct net *net)
{
	struct cfg802154_registered_device *rdev;

	rtnl_lock();
	list_for_each_entry(rdev, &cfg802154_rdev_list, list) {
		if (net_eq(wpan_phy_net(&rdev->wpan_phy), net))
			WARN_ON(cfg802154_switch_netns(rdev, &init_net));
	}
	rtnl_unlock();
}

static struct pernet_operations cfg802154_pernet_ops = {
	.exit = cfg802154_pernet_exit,
};

static int __init cfg802154_init(void)
{
	int err;

	err = register_pernet_device(&cfg802154_pernet_ops);
	if (err)
		goto out_fail_pernet;

	err = wpan_phy_sysfs_init();
	if (err)
		goto out_fail_sysfs;

	err = register_netdevice_notifier(&cfg802154_netdev_notifier);
	if (err)
		goto out_fail_notifier;

	err = nl802154_init();
	if (err)
		goto out_fail_nl802154;

	return 0;

out_fail_nl802154:
	unregister_netdevice_notifier(&cfg802154_netdev_notifier);
out_fail_notifier:
	wpan_phy_sysfs_exit();
out_fail_sysfs:
	unregister_pernet_device(&cfg802154_pernet_ops);
out_fail_pernet:
	return err;
}
subsys_initcall(cfg802154_init);

static void __exit cfg802154_exit(void)
{
	nl802154_exit();
	unregister_netdevice_notifier(&cfg802154_netdev_notifier);
	wpan_phy_sysfs_exit();
	unregister_pernet_device(&cfg802154_pernet_ops);
}
module_exit(cfg802154_exit);

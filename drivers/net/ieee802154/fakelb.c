/*
 * Loopback IEEE 802.15.4 interface
 *
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
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <net/mac802154.h>
#include <net/cfg802154.h>

static int numlbs = 2, whitelist;

static LIST_HEAD(fakelb_phys);
static DEFINE_MUTEX(fakelb_phys_lock);

static LIST_HEAD(fakelb_ifup_phys);
static DEFINE_RWLOCK(fakelb_ifup_phys_lock);

struct fakelb_phy {
	struct ieee802154_hw *hw;

	u8 page;
	u8 channel;

	bool suspended;

	struct list_head list;
	struct list_head list_ifup;
	struct list_head edges;
	rwlock_t edges_lock;
	bool ignore;
};

struct fakelb_edge {
	struct fakelb_phy *endpoint;
	u8 lqi;

	struct list_head list;
};

static int fakelb_hw_ed(struct ieee802154_hw *hw, u8 *level)
{
	BUG_ON(!level);
	*level = 0xbe;

	return 0;
}

static int fakelb_hw_channel(struct ieee802154_hw *hw, u8 page, u8 channel)
{
	struct fakelb_phy *phy = hw->priv;

	write_lock_bh(&fakelb_ifup_phys_lock);
	phy->page = page;
	phy->channel = channel;
	write_unlock_bh(&fakelb_ifup_phys_lock);
	return 0;
}

static int fakelb_hw_xmit_all_to_all(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	struct fakelb_phy *current_phy = hw->priv, *phy;
	struct ieee802154_rx_info rx_info;

	read_lock_bh(&fakelb_ifup_phys_lock);
	WARN_ON(current_phy->suspended);
	list_for_each_entry(phy, &fakelb_ifup_phys, list_ifup) {
		if (current_phy == phy)
			continue;

		if (current_phy->page == phy->page &&
		    current_phy->channel == phy->channel) {
			struct sk_buff *newskb = pskb_copy(skb, GFP_ATOMIC);

			get_random_bytes(&rx_info, sizeof(rx_info));
		
			if (newskb)
				ieee802154_rx_irqsafe(phy->hw, newskb, &rx_info);
		}
	}
	read_unlock_bh(&fakelb_ifup_phys_lock);

	ieee802154_xmit_complete(hw, skb, false, IEEE802154_TX_SUCCESS);
	return 0;
}

static int fakelb_hw_xmit_whitelist(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	struct fakelb_phy *current_phy = hw->priv, *phy;
	struct ieee802154_rx_info rx_info;
	struct fakelb_edge *e;

	read_lock_bh(&fakelb_ifup_phys_lock);
	read_lock_bh(&current_phy->edges_lock);
	list_for_each_entry(e, &current_phy->edges, list) {
		phy = e->endpoint;

		if (current_phy->page == phy->page &&
		    current_phy->channel == phy->channel) {
			struct sk_buff *newskb = pskb_copy(skb, GFP_ATOMIC);

			rx_info.lqi = e->lqi;
		
			if (newskb)
				ieee802154_rx_irqsafe(phy->hw, newskb, &rx_info);
		}
	}
	read_unlock_bh(&current_phy->edges_lock);
	read_unlock_bh(&fakelb_ifup_phys_lock);

	ieee802154_xmit_complete(hw, skb, false, IEEE802154_TX_SUCCESS);
	return 0;
}

static int fakelb_hw_xmit(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	if (whitelist)
		return fakelb_hw_xmit_whitelist(hw, skb);
	else
		return fakelb_hw_xmit_all_to_all(hw, skb);
}

static int fakelb_hw_start(struct ieee802154_hw *hw)
{
	struct fakelb_phy *phy = hw->priv;

	write_lock_bh(&fakelb_ifup_phys_lock);
	phy->suspended = false;
	list_add(&phy->list_ifup, &fakelb_ifup_phys);
	write_unlock_bh(&fakelb_ifup_phys_lock);

	return 0;
}

static void fakelb_hw_stop(struct ieee802154_hw *hw)
{
	struct fakelb_phy *phy = hw->priv;

	write_lock_bh(&fakelb_ifup_phys_lock);
	phy->suspended = true;
	list_del(&phy->list_ifup);
	write_unlock_bh(&fakelb_ifup_phys_lock);
}

static int
fakelb_set_promiscuous_mode(struct ieee802154_hw *hw, const bool on)
{
	return 0;
}

static const struct ieee802154_ops fakelb_ops = {
	.owner = THIS_MODULE,
	.xmit_async = fakelb_hw_xmit,
	.ed = fakelb_hw_ed,
	.set_channel = fakelb_hw_channel,
	.start = fakelb_hw_start,
	.stop = fakelb_hw_stop,
	.set_promiscuous_mode = fakelb_set_promiscuous_mode,
};

/* Number of dummy devices to be set up by this module. */
module_param(numlbs, int, 0);
MODULE_PARM_DESC(numlbs, " number of pseudo devices");

module_param(whitelist, int, 0);
MODULE_PARM_DESC(whitelist, " bool whitelist for edges");

static struct dentry *fakelb_debugfs_root;

static int fakelb_stats_show(struct seq_file *file, void *offset)
{
	struct fakelb_phy *phy;
	struct fakelb_edge *e;

	mutex_lock(&fakelb_phys_lock);
	list_for_each_entry(phy, &fakelb_phys, list) {
		if (phy->ignore)
			continue;

		read_lock_bh(&phy->edges_lock);
		list_for_each_entry(e, &phy->edges, list) {
			if (e->endpoint->ignore)
				continue;

			seq_printf(file, "\t%s -> %s[label=\"%d\"];\n",
				   dev_name(&phy->hw->phy->dev),
				   dev_name(&e->endpoint->hw->phy->dev),
				   e->lqi);

		}
		read_unlock_bh(&phy->edges_lock);
	}
	mutex_unlock(&fakelb_phys_lock);
	seq_printf(file, "}\n");

	return 0;
}

static int fakelb_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, fakelb_stats_show, inode->i_private);
}

static struct fakelb_phy *fakelb_phy_by_idx(unsigned int idx)
{
	struct fakelb_phy *phy;
	char buf[128] = {};
	int n;

	n = sprintf(buf, "phy%u", idx);
	if (n < 0)
		return NULL;

	list_for_each_entry(phy, &fakelb_phys, list) {
		if (!strncmp(buf, dev_name(&phy->hw->phy->dev), sizeof(buf)))
			return phy;
	}

	return NULL;
}

static struct fakelb_edge *fakelb_hw_get_edge(struct fakelb_phy *v0, struct fakelb_phy *v1)
{
	struct fakelb_edge *e;

	list_for_each_entry(e, &v0->edges, list) {
		if (e->endpoint == v1)
		       return e;	
	}

	return NULL;
}


static int fakelb_edges_add(char *argv)
{
	struct fakelb_phy *v0, *v1;
	struct fakelb_edge *e;
	unsigned int v[2];
	int n;

	n = sscanf(argv, "%d %d", &v[0], &v[1]);
	if (n != 2) {
	       return -ENOENT;
	}

	if (v[0] == v[1])
	       return -EINVAL;

	mutex_lock(&fakelb_phys_lock);

	v0 = fakelb_phy_by_idx(v[0]);
	v1 = fakelb_phy_by_idx(v[1]);
	if (!v0 || !v1) {
	       mutex_unlock(&fakelb_phys_lock);
	       return -ENOENT;
	}

	write_lock_bh(&v0->edges_lock);
	e = fakelb_hw_get_edge(v0, v1);
	if (e) {
	       write_unlock_bh(&v0->edges_lock);
	       mutex_unlock(&fakelb_phys_lock);
	       return -EEXIST;
	}

	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e) {
	       write_unlock_bh(&v0->edges_lock);
	       mutex_unlock(&fakelb_phys_lock);
	       return -ENOMEM;
	}

	e->lqi = 0xff;
	e->endpoint = v1;

	list_add_tail(&e->list, &v0->edges);
	
	write_unlock_bh(&v0->edges_lock);
	mutex_unlock(&fakelb_phys_lock);

	return 0;
}

static int fakelb_edges_del(char *argv)
{
	struct fakelb_phy *v0, *v1;
	struct fakelb_edge *e;
	unsigned int v[2];
	int n;

	n = sscanf(argv, "%d %d", &v[0], &v[1]);
	if (n != 2)
	       return -ENOENT;

	if (v[0] == v[1])
	       return -EINVAL;

	mutex_lock(&fakelb_phys_lock);
	v0 = fakelb_phy_by_idx(v[0]);
	v1 = fakelb_phy_by_idx(v[1]);
	if (!v0 || !v1) {
	       mutex_unlock(&fakelb_phys_lock);
	       return -ENOENT;
	}

	write_lock_bh(&v0->edges_lock);
	e = fakelb_hw_get_edge(v0, v1);
	if (!e) {
	       write_unlock_bh(&v0->edges_lock);
	       mutex_unlock(&fakelb_phys_lock);
	       return -ENOENT;
	} else {
		list_del(&e->list);
	}
	write_unlock_bh(&v0->edges_lock);

	mutex_unlock(&fakelb_phys_lock);

	return 0;
}

static int fakelb_edges_lqi(char *argv)
{
	struct fakelb_phy *v0, *v1;
	struct fakelb_edge *e;
	unsigned int v[2];
	unsigned int lqi;
	int n;

	n = sscanf(argv, "%d %d %x", &v[0], &v[1], &lqi);
	if (n != 3)
	       return -ENOENT;

	if (v[0] == v[1])
	       return -EINVAL;

	mutex_lock(&fakelb_phys_lock);
	v0 = fakelb_phy_by_idx(v[0]);
	v1 = fakelb_phy_by_idx(v[1]);
	if (!v0 || !v1) {
	       mutex_unlock(&fakelb_phys_lock);
	       return -ENOENT;
	}

	write_lock_bh(&v0->edges_lock);
	e = fakelb_hw_get_edge(v0, v1);
	if (!e) {
		write_unlock_bh(&v0->edges_lock);
		mutex_unlock(&fakelb_phys_lock);
		return -ENOENT;
	} else {
		e->lqi = lqi;
	}
	write_unlock_bh(&v0->edges_lock);

	mutex_unlock(&fakelb_phys_lock);

	return 0;
}

static int fakelb_edges_ignore(char *argv)
{
	struct fakelb_phy *v;
	unsigned int num;
	int n;

	n = sscanf(argv, "%d", &num);
	if (n != 1)
	       return -ENOENT;

	mutex_lock(&fakelb_phys_lock);
	v = fakelb_phy_by_idx(num);
	if (!v) {
	       mutex_unlock(&fakelb_phys_lock);
	       return -ENOENT;
	}

	v->ignore = true;

	mutex_unlock(&fakelb_phys_lock);

	return 0;
}

static ssize_t fakelb_edges_write(struct file *fp,
				  const char __user *user_buf, size_t count,
				  loff_t *ppos)
{
	char buf[128] = {};
	int status = count, err;

	if (copy_from_user(&buf, user_buf, min_t(size_t, sizeof(buf) - 1,
						 count))) {
		status = -EFAULT;
		goto out;
	}

	if (!strncmp(buf, "add ", 4)) {
		err = fakelb_edges_add(&buf[4]);
		if (err < 0)
			status = err;
	} else if (!strncmp(buf, "del ", 4)) {
		err = fakelb_edges_del(&buf[4]);
		if (err < 0)
			status = err;
	} else if (!strncmp(buf, "ign ", 4)) {
		err = fakelb_edges_ignore(&buf[4]);
		if (err < 0)
			status = err;
	} else if (!strncmp(buf, "lqi ", 4)) {
		err = fakelb_edges_lqi(&buf[4]);
		if (err < 0)
			status = err;
	} else {
		status = -EINVAL;
		goto out;
	}

out:
	return status;
}

static const struct file_operations fakelb_edges_fops = {
	.open		= fakelb_stats_open,
	.read		= seq_read,
	.write		= fakelb_edges_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int fakelb_debugfs_init(void)
{
	char debugfs_dir_name[DNAME_INLINE_LEN + 1] = "fakelb";
	struct dentry *stats;

	fakelb_debugfs_root = debugfs_create_dir(debugfs_dir_name, NULL);
	if (!fakelb_debugfs_root)
		return -ENOMEM;

	stats = debugfs_create_file("edges", S_IWUGO,
				    fakelb_debugfs_root, NULL,
				    &fakelb_edges_fops);
	if (!stats)
		return -ENOMEM;

	return 0;
}

static void fakelb_debugfs_remove(void)
{
	debugfs_remove_recursive(fakelb_debugfs_root);
}

static int fakelb_add_one(struct device *dev)
{
	struct ieee802154_hw *hw;
	struct fakelb_phy *phy;
	int err;

	hw = ieee802154_alloc_hw(sizeof(*phy), &fakelb_ops);
	if (!hw)
		return -ENOMEM;

	phy = hw->priv;
	phy->hw = hw;

	/* 868 MHz BPSK	802.15.4-2003 */
	hw->phy->supported.channels[0] |= 1;
	/* 915 MHz BPSK	802.15.4-2003 */
	hw->phy->supported.channels[0] |= 0x7fe;
	/* 2.4 GHz O-QPSK 802.15.4-2003 */
	hw->phy->supported.channels[0] |= 0x7FFF800;
	/* 868 MHz ASK 802.15.4-2006 */
	hw->phy->supported.channels[1] |= 1;
	/* 915 MHz ASK 802.15.4-2006 */
	hw->phy->supported.channels[1] |= 0x7fe;
	/* 868 MHz O-QPSK 802.15.4-2006 */
	hw->phy->supported.channels[2] |= 1;
	/* 915 MHz O-QPSK 802.15.4-2006 */
	hw->phy->supported.channels[2] |= 0x7fe;
	/* 2.4 GHz CSS 802.15.4a-2007 */
	hw->phy->supported.channels[3] |= 0x3fff;
	/* UWB Sub-gigahertz 802.15.4a-2007 */
	hw->phy->supported.channels[4] |= 1;
	/* UWB Low band 802.15.4a-2007 */
	hw->phy->supported.channels[4] |= 0x1e;
	/* UWB High band 802.15.4a-2007 */
	hw->phy->supported.channels[4] |= 0xffe0;
	/* 750 MHz O-QPSK 802.15.4c-2009 */
	hw->phy->supported.channels[5] |= 0xf;
	/* 750 MHz MPSK 802.15.4c-2009 */
	hw->phy->supported.channels[5] |= 0xf0;
	/* 950 MHz BPSK 802.15.4d-2009 */
	hw->phy->supported.channels[6] |= 0x3ff;
	/* 950 MHz GFSK 802.15.4d-2009 */
	hw->phy->supported.channels[6] |= 0x3ffc00;

	ieee802154_random_extended_addr(&hw->phy->perm_extended_addr);
	/* fake phy channel 13 as default */
	hw->phy->current_channel = 13;
	phy->channel = hw->phy->current_channel;

	hw->flags = IEEE802154_HW_PROMISCUOUS;
	hw->parent = dev;
	INIT_LIST_HEAD(&phy->edges);
	rwlock_init(&phy->edges_lock);

	err = ieee802154_register_hw(hw);
	if (err)
		goto err_reg;

	mutex_lock(&fakelb_phys_lock);
	list_add_tail(&phy->list, &fakelb_phys);
	mutex_unlock(&fakelb_phys_lock);

	return 0;

err_reg:
	ieee802154_free_hw(phy->hw);
	return err;
}

static void fakelb_del(struct fakelb_phy *phy)
{
	list_del(&phy->list);

	ieee802154_unregister_hw(phy->hw);
	ieee802154_free_hw(phy->hw);
}

static int fakelb_probe(struct platform_device *pdev)
{
	struct fakelb_phy *phy, *tmp;
	int err, i;

	for (i = 0; i < numlbs; i++) {
		err = fakelb_add_one(&pdev->dev);
		if (err < 0)
			goto err_slave;
	}

	dev_info(&pdev->dev, "added ieee802154 hardware\n");

	return fakelb_debugfs_init();

err_slave:
	mutex_lock(&fakelb_phys_lock);
	list_for_each_entry_safe(phy, tmp, &fakelb_phys, list)
		fakelb_del(phy);
	mutex_unlock(&fakelb_phys_lock);
	return err;
}

static int fakelb_remove(struct platform_device *pdev)
{
	struct fakelb_phy *phy, *tmp;

	mutex_lock(&fakelb_phys_lock);
	list_for_each_entry_safe(phy, tmp, &fakelb_phys, list)
		fakelb_del(phy);
	mutex_unlock(&fakelb_phys_lock);

	fakelb_debugfs_remove();

	return 0;
}

static struct platform_device *ieee802154fake_dev;

static struct platform_driver ieee802154fake_driver = {
	.probe = fakelb_probe,
	.remove = fakelb_remove,
	.driver = {
			.name = "ieee802154fakelb",
	},
};

static __init int fakelb_init_module(void)
{
	ieee802154fake_dev = platform_device_register_simple(
			     "ieee802154fakelb", -1, NULL, 0);
	return platform_driver_register(&ieee802154fake_driver);
}

static __exit void fake_remove_module(void)
{
	platform_driver_unregister(&ieee802154fake_driver);
	platform_device_unregister(ieee802154fake_dev);
}

module_init(fakelb_init_module);
module_exit(fake_remove_module);
MODULE_LICENSE("GPL");

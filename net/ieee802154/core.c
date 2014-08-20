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

#define PHY_NAME "phy"

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>

#include <net/cfg802154.h>

#include "ieee802154.h"
#include "core.h"
#include "sysfs.h"

struct wpan_phy *wpan_phy_new(const struct cfg802154_ops *ops,
			      size_t sizeof_priv)
{
	static atomic_t wpan_phy_counter = ATOMIC_INIT(0);
	struct cfg802154_registered_device *rdev;
	size_t alloc_size;

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

	device_initialize(&rdev->wpan_phy.dev);
	rdev->wpan_phy.dev.class = &ieee802154_class;
	rdev->wpan_phy.dev.platform_data = rdev;

	mutex_init(&rdev->wpan_phy.pib_lock);

	/* not initialised */
	rdev->wpan_phy.current_channel = -1;
	/* for compatibility */
	rdev->wpan_phy.current_page = 0;

	wpan_phy_net_set(&rdev->wpan_phy, &init_net);

	return &rdev->wpan_phy;
}
EXPORT_SYMBOL(wpan_phy_new);

int wpan_phy_register(struct wpan_phy *phy)
{
	return device_add(&phy->dev);
}
EXPORT_SYMBOL(wpan_phy_register);

void wpan_phy_unregister(struct wpan_phy *phy)
{
	device_del(&phy->dev);
}
EXPORT_SYMBOL(wpan_phy_unregister);

void wpan_phy_free(struct wpan_phy *phy)
{
	put_device(&phy->dev);
}
EXPORT_SYMBOL(wpan_phy_free);

static int __init wpan_phy_class_init(void)
{
	int rc;

	rc = wpan_phy_sysfs_init();
	if (rc)
		goto err;

	return 0;
err:
	return rc;
}
subsys_initcall(wpan_phy_class_init);

static void __exit wpan_phy_class_exit(void)
{
	wpan_phy_sysfs_exit();
}
module_exit(wpan_phy_class_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IEEE 802.15.4 configuration interface");
MODULE_AUTHOR("Dmitry Eremin-Solenikov");


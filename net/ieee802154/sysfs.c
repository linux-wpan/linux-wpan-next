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
 * Based on: net/wireless/sysfs.c
 */

#include <linux/device.h>

#include <net/cfg802154.h>

#include "core.h"

static inline struct cfg802154_registered_device *
dev_to_rdev(struct device *dev)
{
	return container_of(dev, struct cfg802154_registered_device, wpan_phy.dev);
}

#define SHOW_FMT(name, fmt, member)					\
static ssize_t name ## _show(struct device *dev,			\
			     struct device_attribute *attr,		\
			     char *buf)					\
{									\
	return sprintf(buf, fmt "\n", dev_to_rdev(dev)->member);	\
}									\
static DEVICE_ATTR_RO(name)

SHOW_FMT(index, "%d", wpan_phy_idx);

static ssize_t name_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf) 
{
	struct wpan_phy *wpan_phy = &dev_to_rdev(dev)->wpan_phy;
	return sprintf(buf, "%s\n", dev_name(&wpan_phy->dev));
}
static DEVICE_ATTR_RO(name);

static struct attribute *ieee802154_attrs[] = {
	&dev_attr_index.attr,
	&dev_attr_name.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ieee802154);

static void wpan_phy_dev_release(struct device *dev)
{
	struct wpan_phy *phy = container_of(dev, struct wpan_phy, dev);

	kfree(phy);
}

static const void *wpan_phy_namespace(struct device *d)
{
        struct wpan_phy *wpan_phy = container_of(d, struct wpan_phy, dev);

        return wpan_phy_net(wpan_phy);
}

struct class ieee802154_class = {
	.name = "ieee802154",
	.dev_release = wpan_phy_dev_release,
	.dev_groups = ieee802154_groups,
	.ns_type = &net_ns_type_operations,
	.namespace = wpan_phy_namespace,
};

int wpan_phy_sysfs_init(void)
{
	return class_register(&ieee802154_class);
}

void wpan_phy_sysfs_exit(void)
{
	class_unregister(&ieee802154_class);
}

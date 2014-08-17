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

#define MASTER_SHOW_COMPLEX(name, format_string, args...)		\
static ssize_t name ## _show(struct device *dev,			\
			    struct device_attribute *attr, char *buf)	\
{									\
	struct wpan_phy *phy = container_of(dev, struct wpan_phy, dev);	\
	int ret;							\
									\
	mutex_lock(&phy->pib_lock);					\
	ret = snprintf(buf, PAGE_SIZE, format_string "\n", args);	\
	mutex_unlock(&phy->pib_lock);					\
	return ret;							\
}									\
static DEVICE_ATTR_RO(name);

#define MASTER_SHOW(field, format_string)				\
	MASTER_SHOW_COMPLEX(field, format_string, phy->field)

MASTER_SHOW(current_channel, "%d");
MASTER_SHOW(current_page, "%d");
MASTER_SHOW(transmit_power, "%d +- 1 dB");
MASTER_SHOW(cca_mode, "%d");

static ssize_t channels_supported_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct wpan_phy *phy = container_of(dev, struct wpan_phy, dev);
	int ret;
	int i, len = 0;

	mutex_lock(&phy->pib_lock);
	for (i = 0; i < 32; i++) {
		ret = snprintf(buf + len, PAGE_SIZE - len,
			       "%#09x\n", phy->channels_supported[i]);
		if (ret < 0)
			break;
		len += ret;
	}
	mutex_unlock(&phy->pib_lock);
	return len;
}
static DEVICE_ATTR_RO(channels_supported);

static struct attribute *pmib_attrs[] = {
	&dev_attr_current_channel.attr,
	&dev_attr_current_page.attr,
	&dev_attr_channels_supported.attr,
	&dev_attr_transmit_power.attr,
	&dev_attr_cca_mode.attr,
	NULL,
};
ATTRIBUTE_GROUPS(pmib);

static void wpan_phy_release(struct device *d)
{
	struct wpan_phy *phy = container_of(d, struct wpan_phy, dev);

	kfree(phy);
}

static struct class wpan_phy_class = {
	.name = "ieee802154",
	.dev_release = wpan_phy_release,
	.dev_groups = pmib_groups,
};

static int wpan_phy_match(struct device *dev, const void *data)
{
	return !strcmp(dev_name(dev), (const char *)data);
}

struct wpan_phy *wpan_phy_find(const char *str)
{
	struct device *dev;

	if (WARN_ON(!str))
		return NULL;

	dev = class_find_device(&wpan_phy_class, NULL, str, wpan_phy_match);
	if (!dev)
		return NULL;

	return container_of(dev, struct wpan_phy, dev);
}
EXPORT_SYMBOL(wpan_phy_find);

struct wpan_phy_iter_data {
	int (*fn)(struct wpan_phy *phy, void *data);
	void *data;
};

static int wpan_phy_iter(struct device *dev, void *_data)
{
	struct wpan_phy_iter_data *wpid = _data;
	struct wpan_phy *phy = container_of(dev, struct wpan_phy, dev);

	return wpid->fn(phy, wpid->data);
}

int wpan_phy_for_each(int (*fn)(struct wpan_phy *phy, void *data),
		      void *data)
{
	struct wpan_phy_iter_data wpid = {
		.fn = fn,
		.data = data,
	};

	return class_for_each_device(&wpan_phy_class, NULL,
			&wpid, wpan_phy_iter);
}
EXPORT_SYMBOL(wpan_phy_for_each);

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
	rdev->wpan_phy.dev.class = &wpan_phy_class;
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

	rc = class_register(&wpan_phy_class);
	if (rc)
		goto err;

	return 0;
err:
	return rc;
}
subsys_initcall(wpan_phy_class_init);

static void __exit wpan_phy_class_exit(void)
{
	class_unregister(&wpan_phy_class);
}
module_exit(wpan_phy_class_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("IEEE 802.15.4 configuration interface");
MODULE_AUTHOR("Dmitry Eremin-Solenikov");


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
 * Based on: net/mac80211/cfg.c
 */

#include "driver-ops.h"
#include "ieee802154_i.h"

static struct wpan_dev *ieee802154_add_iface(struct wpan_phy *phy,
					     const char *name,
					     enum nl802154_iftype type)
{
	struct ieee802154_local *local = wpan_phy_priv(phy);
	struct wpan_dev *wpan_dev;
	int err;

	err = ieee802154_if_add(local, name, &wpan_dev, type);
	if (err)
		return ERR_PTR(err);

	return wpan_dev;
}

static int ieee802154_del_iface(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev)
{
	ieee802154_if_remove(IEEE802154_WPAN_DEV_TO_SUB_IF(wpan_dev));

	return 0;
}

static int
ieee802154_set_channel(struct wpan_phy *wpan_phy, u8 channel)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	u8 current_channel = wpan_phy->current_channel;
	u8 current_page = wpan_phy->current_page;
	int ret;

	ASSERT_RTNL();

	if (current_channel == channel)
		return 0;

	if (!(wpan_phy->channels_supported[current_page] & BIT(channel)))
		return -EINVAL;
	
	ret = drv_set_channel(local, current_page, channel);
	if (!ret)
		wpan_phy->current_channel = channel;
	
	return ret;
}

static int
ieee802154_set_page(struct wpan_phy *wpan_phy, u8 page)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	u8 current_channel = wpan_phy->current_channel;
	u8 current_page = wpan_phy->current_page;
	int ret;

	ASSERT_RTNL();

	if (current_page == page)
		return 0;

	if (!(wpan_phy->channels_supported[page] & BIT(current_channel)))
		return -EINVAL;
	
	ret = drv_set_channel(local, page, current_channel);
	if (!ret)
		wpan_phy->current_page = page;

	return ret;
}

static int ieee802154_set_pan_id(struct wpan_phy *wpan_phy,
				 struct wpan_dev *wpan_dev, u16 pan_id)
{
	u16 current_pan_id = le16_to_cpu(wpan_dev->pan_id);

	ASSERT_RTNL();

	if (current_pan_id == pan_id)
		return 0;

	wpan_dev->pan_id = cpu_to_le16(pan_id);

	return 0;
}

const struct cfg802154_ops mac802154_config_ops = {
	.add_virtual_intf = ieee802154_add_iface,
	.del_virtual_intf = ieee802154_del_iface,
	.set_channel = ieee802154_set_channel,
	.set_page = ieee802154_set_page,
	.set_pan_id = ieee802154_set_pan_id,
};

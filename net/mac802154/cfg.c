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

const struct cfg802154_ops mac802154_config_ops = {
	.add_virtual_intf = ieee802154_add_iface,
	.del_virtual_intf = ieee802154_del_iface,
};

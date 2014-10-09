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

static int
ieee802154_set_tx_power(struct wpan_phy *wpan_phy, s8 dbm)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	u8 current_tx_power = wpan_phy->transmit_power;
	int ret;

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_TXPOWER))
		return -EOPNOTSUPP;

	if (current_tx_power == dbm)
		return 0;

	ret = drv_set_tx_power(local, dbm);
	if (!ret)
		wpan_phy->transmit_power = dbm;

	return ret;
}

static int
ieee802154_set_cca_mode(struct wpan_phy *wpan_phy, const u8 cca_mode,
			const bool cca_mode3_and)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	u8 current_cca_mode = wpan_phy->cca_mode;
	bool current_cca_mode3_and = wpan_phy->cca_mode3_and;
	int ret;

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_CCA_MODE))
		return -EOPNOTSUPP;

	if (current_cca_mode == cca_mode &&
	    current_cca_mode3_and == cca_mode3_and)
		return 0;

	ret = drv_set_cca_mode(local, cca_mode, cca_mode3_and);
	if (!ret) {
		wpan_phy->cca_mode = cca_mode;
		wpan_phy->cca_mode3_and = cca_mode3_and;
	}

	return ret;
}

static int
ieee802154_set_cca_ed_level(struct wpan_phy *wpan_phy, const s32 ed_level)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_CCA_ED_LEVEL))
		return -EOPNOTSUPP;

	return drv_set_cca_ed_level(local, ed_level);
}

static int ieee802154_set_pan_id(struct wpan_phy *wpan_phy,
				 struct wpan_dev *wpan_dev, u16 pan_id)
{
	const __le16 __le16_pan_id = cpu_to_le16(pan_id);

	ASSERT_RTNL();

	wpan_dev->pan_id = __le16_pan_id;
	return 0;
}

static int ieee802154_set_short_addr(struct wpan_phy *wpan_phy,
				     struct wpan_dev *wpan_dev, u16 short_addr)
{
	const __le16 __le16_short_addr = cpu_to_le16(short_addr);

	ASSERT_RTNL();

	wpan_dev->short_addr = __le16_short_addr;
	return 0;
}

static int ieee802154_set_max_frame_retries(struct wpan_phy *wpan_phy,
					    struct wpan_dev *wpan_dev,
					    s8 max_frame_retries)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_FRAME_RETRIES))
		return -EOPNOTSUPP;

	wpan_dev->frame_retries = max_frame_retries;
	return 0;
}

static int ieee802154_set_max_be(struct wpan_phy *wpan_phy,
				 struct wpan_dev *wpan_dev,
				 const u8 max_be)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_CSMA_PARAMS))
		return -EOPNOTSUPP;

	wpan_dev->max_be = max_be;
	return 0;
}

static int ieee802154_set_max_csma_backoffs(struct wpan_phy *wpan_phy,
					    struct wpan_dev *wpan_dev,
					    const u8 max_csma_backoffs)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_CSMA_PARAMS))
		return -EOPNOTSUPP;

	wpan_dev->csma_retries = max_csma_backoffs;
	return 0;
}

static int ieee802154_set_min_be(struct wpan_phy *wpan_phy,
				 struct wpan_dev *wpan_dev,
				 const u8 min_be)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_CSMA_PARAMS))
		return -EOPNOTSUPP;

	wpan_dev->min_be = min_be;
	return 0;
}

static int ieee802154_set_lbt_mode(struct wpan_phy *wpan_phy,
				   struct wpan_dev *wpan_dev,
				   const bool mode)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);

	ASSERT_RTNL();

	if (!(local->hw.flags & IEEE802154_HW_LBT))
		return -EOPNOTSUPP;

	wpan_dev->lbt = mode;
	return 0;
}

const struct cfg802154_ops mac802154_config_ops = {
	.add_virtual_intf = ieee802154_add_iface,
	.del_virtual_intf = ieee802154_del_iface,
	.set_channel = ieee802154_set_channel,
	.set_page = ieee802154_set_page,
	.set_tx_power = ieee802154_set_tx_power,
	.set_cca_mode = ieee802154_set_cca_mode,
	.set_cca_ed_level = ieee802154_set_cca_ed_level,
	.set_pan_id = ieee802154_set_pan_id,
	.set_short_addr = ieee802154_set_short_addr,
	.set_max_frame_retries = ieee802154_set_max_frame_retries,
	.set_max_be = ieee802154_set_max_be,
	.set_max_csma_backoffs = ieee802154_set_max_csma_backoffs,
	.set_min_be = ieee802154_set_min_be,
	.set_lbt_mode = ieee802154_set_lbt_mode,
};

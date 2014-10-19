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
 * Written by:
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#ifndef __NET_CFG802154_H
#define __NET_CFG802154_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/mutex.h>
#include <linux/bug.h>
#include <linux/nl802154.h>

struct wpan_phy;

/* According to the IEEE 802.15.4 stadard the upper most significant bits of
 * the 32-bit channel bitmaps shall be used as an integer value to specify 32
 * possible channel pages. The lower 27 bits of the channel bit map shall be
 * used as a bit mask to specify channel numbers within a channel page.
 */
#define WPAN_NUM_CHANNELS	27
#define WPAN_NUM_PAGES		32

struct cfg802154_ops {
	struct wpan_dev * (*add_virtual_intf)(struct wpan_phy *wpan_phy,
					      const char *name,
					      enum nl802154_iftype type);
	int	(*del_virtual_intf)(struct wpan_phy *wpan_phy,
				    struct wpan_dev *wpan_dev);
	int	(*set_channel)(struct wpan_phy *wpan_phy, u8 channel);
	int	(*set_page)(struct wpan_phy *wpan_phy, u8 page);
	int	(*set_tx_power)(struct wpan_phy *wpan_phy, s8 dbm);
	int	(*set_cca_mode)(struct wpan_phy *wpan_phy, const u8 cca_mode,
				const bool cca_mode3_and);
	int	(*set_cca_ed_level)(struct wpan_phy *wpan_phy, const s32 ed_level);
	int	(*set_pan_id)(struct wpan_phy *wpan_phy,
			      struct wpan_dev *wpan_dev, u16 pan_id);
	int	(*set_short_addr)(struct wpan_phy *wpan_phy,
				  struct wpan_dev *wpan_dev, u16 short_addr);
	int	(*set_max_frame_retries)(struct wpan_phy *wpan_phy,
					 struct wpan_dev *wpan_dev,
					 s8 max_frame_retries);
	int	(*set_max_be)(struct wpan_phy *wpan_phy,
			      struct wpan_dev *wpan_dev, u8 max_be);
	int	(*set_max_csma_backoffs)(struct wpan_phy *wpan_phy,
					 struct wpan_dev *wpan_dev,
					 u8 max_csma_backoffs);
	int	(*set_min_be)(struct wpan_phy *wpan_phy,
			      struct wpan_dev *wpan_dev, u8 min_be);
	int	(*set_lbt_mode)(struct wpan_phy *wpan_phy,
				struct wpan_dev *wpan_dev, const bool mode);
};

/**
 * enum wpan_phy_flags - wpan_phy capability flags
 *
 * @WPAN_PHY_FLAG_NETNS_OK: if not set, do not allow changing the netns of
 *	this wpan phy at all
 */
enum wpan_phy_flags {
	WPAN_PHY_FLAG_NETNS_OK = BIT(3),
};

struct wpan_phy {
	u32 flags;

	/*
	 * This is a PIB according to 802.15.4-2011.
	 * We do not provide timing-related variables, as they
	 * aren't used outside of driver
	 */
	u8 current_channel;
	u8 current_page;
	u32 channels_supported[32];
	s8 transmit_power;
	u8 cca_mode;
	bool cca_mode3_and;

	__le64 perm_extended_addr;

	struct device dev;
	int idx;

#ifdef CONFIG_NET_NS
	/* the network namespace this phy lives in currently */
	struct net *_net;
#endif

	/* protects ->resume, ->suspend sysfs callbacks against unregister hw */
	bool registered;

	char priv[0] __attribute__((__aligned__(NETDEV_ALIGN)));
};

struct wpan_dev {
	struct wpan_phy *wpan_phy;
	enum nl802154_iftype iftype;

	/* the remainder of this struct should be private to cfg802154 */
	struct list_head list;
	struct net_device *netdev;
	struct net_device *lowpan_dev;

	u32 identifier;

	u32 owner_nlportid;

	/* MAC PIB */
	__le64 extended_addr;
	__le16 short_addr;
	__le16 pan_id;

	/* MAC BSN field */
	u8 bsn;
	/* MAC DSN field */
	u8 dsn;

	u8 min_be;
	u8 max_be;
	u8 csma_retries;
	s8 frame_retries;

	bool lbt;

	bool promiscuous_mode;
};

static inline bool wpan_dev_is_monitor(const struct wpan_dev *wpan_dev)
{
	return wpan_dev->iftype == NL802154_IFTYPE_MONITOR;
}

static inline bool wpan_dev_is_coord(const struct wpan_dev *wpan_dev)
{
	return wpan_dev->iftype == NL802154_IFTYPE_COORD;
}

static inline bool wpan_dev_is_node(const struct wpan_dev *wpan_dev)
{
	return wpan_dev->iftype == NL802154_IFTYPE_NODE;
}

static inline struct net *wpan_phy_net(struct wpan_phy *phy)
{
	return read_pnet(&phy->_net);
}

static inline void wpan_phy_net_set(struct wpan_phy *phy, struct net *net)
{
	write_pnet(&phy->_net, net);
}

/**
 * set_wpan_phy_dev - set device pointer for wpan phy
 *
 * @phy: The wiphy whose device to bind
 * @dev: The device to parent it to
 */
static inline void set_wpan_phy_dev(struct wpan_phy *phy, struct device *dev)
{
	phy->dev.parent = dev;
}

/**
 * wpan_phy_dev - get wpan phy dev pointer
 *
 * @phy: The wpan phy whose device struct to look up
 * Return: The dev of @phy.
 */
static inline struct device *wpan_phy_dev(struct wpan_phy *phy)
{
	return phy->dev.parent;
}

static inline void *wpan_phy_priv(struct wpan_phy *phy)
{
	BUG_ON(!phy);
	return &phy->priv;
}

struct wpan_phy *wpan_phy_find(const char *str);

static inline void wpan_phy_put(struct wpan_phy *phy)
{
	put_device(&phy->dev);
}

static inline const char *wpan_phy_name(struct wpan_phy *phy)
{
	return dev_name(&phy->dev);
}

struct wpan_phy *wpan_phy_new(const struct cfg802154_ops *ops,
			      size_t sizeof_priv);
int wpan_phy_register(struct wpan_phy *phy);
void wpan_phy_unregister(struct wpan_phy *phy);
void wpan_phy_free(struct wpan_phy *phy);
/* Same semantics as for class_for_each_device */
int wpan_phy_for_each(int (*fn)(struct wpan_phy *phy, void *data), void *data);
/**
 * cfg802154_unregister_wpan_dev - remove the given wpan_dev
 * @wdev: struct wpan_dev to remove
 *
 * Call this function only for wdevs that have no netdev assigned,
 * e.g. P2P Devices. It removes the device from the list so that
 * it can no longer be used. It is necessary to call this function
 * even when cfg80211 requests the removal of the interface by
 * calling the del_virtual_intf() callback. The function must also
 * be called when the driver wishes to unregister the wdev, e.g.
 * when the device is unbound from the driver.
 *
 * Requires the RTNL to be held.
 */
void cfg802154_unregister_wpan_dev(struct wpan_dev *wpan_dev);

#endif /* __NET_CFG802154_H */

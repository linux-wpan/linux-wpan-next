/*
 * Internal interfaces for ieee 802.15.4 address family.
 *
 * Copyright 2007, 2008, 2009 Siemens AG
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
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#ifndef __AF802154_H_
#define __AF802154_H_

#include <net/ieee802154.h>

static inline void ieee802154_addr_from_sa(struct ieee802154_addr *addr,
					   const struct ieee802154_addr_sa *sa,
					   const bool src)
{
	switch (sa->mode) {
	case IEEE802154_ADDR_SHORT:
		if (src)
			addr->mode = cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT);
		else
			addr->mode = cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT);
		addr->pan_id = cpu_to_le16(sa->pan_id);
		addr->short_addr = cpu_to_le16(sa->short_addr);
		break;
	case IEEE802154_ADDR_EXTENDED:
		if (src)
			addr->mode = cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED);
		else
			addr->mode = cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED);
		addr->pan_id = cpu_to_le16(sa->pan_id);
		addr->extended_addr = cpu_to_le64(sa->extended_addr);
		break;
	case IEEE802154_ADDR_NONE:
		addr->mode = cpu_to_le16(IEEE802154_FCTL_ADDR_NONE);
		break;
	}
}

static inline void ieee802154_addr_to_sa(struct ieee802154_addr_sa *sa,
					 const struct ieee802154_addr *addr)
{
	switch (addr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		sa->mode = IEEE802154_ADDR_SHORT;
		sa->pan_id = le16_to_cpu(addr->pan_id);
		sa->short_addr = le16_to_cpu(addr->short_addr);
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		sa->mode = IEEE802154_ADDR_SHORT;
		sa->pan_id = le16_to_cpu(addr->pan_id);
		sa->extended_addr = le64_to_cpu(addr->extended_addr);
		break;
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		sa->mode = IEEE802154_ADDR_NONE;
		break;
	}
}

int ieee802154_create_h_data(struct sk_buff *skb,
			     struct wpan_dev *wpan_dev,
			     const struct ieee802154_addr *saddr,
			     const struct ieee802154_addr *daddr,
			     const bool ack_req);
void ieee802154_raw_deliver(struct net_device *dev, struct sk_buff *skb);
int ieee802154_dgram_deliver(struct net_device *dev, struct sk_buff *skb);
struct net_device *ieee802154_get_dev(struct net *net,
				      const struct ieee802154_addr *addr);

#endif

/*
 * Copyright (C) 2014 Alexander Aring, Pengutronix
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/skbuff.h>

#include <net/ieee802154/dev.h>

struct sk_buff *alloc_ieee802154_skb()
{
	struct sk_buff *skb;

	skb = dev_alloc_skb(IEEE802154_MTU + IEEE802154_RESERVED_SIZE);
	if (unlikely(!skb))
		return NULL;

	skb->protocol = htons(ETH_P_IEEE802154);
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_reserve(skb, IEEE802154_RESERVED_SIZE);

	return skb;
}
EXPORT_SYMBOL_GPL(alloc_ieee802154_skb);


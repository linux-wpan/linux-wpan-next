/*
 * IEEE 802.15.4 inteface for userspace
 *
 * Copyright 2007, 2008 Siemens AG
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

#ifndef _AF_IEEE802154_H
#define _AF_IEEE802154_H

#include <linux/types.h>
#include <linux/socket.h>

enum ieee802154_addr_mode {
	IEEE802154_ADDR_NONE		= 0,
	/* IEEE802154_ADDR_RESERVED	= 1, */
	IEEE802154_ADDR_SHORT		= 2,
	IEEE802154_ADDR_EXTENDED	= 3,
};

struct ieee802154_addr_sa {
	enum ieee802154_addr_mode mode;
	__u16 pan_id;
	union {
		__u64 extended_addr;
		__u16 short_addr;
	};
};

#define IEEE802154_PANID_BROADCAST	0xffff
#define IEEE802154_ADDR_BROADCAST	0xffff
#define IEEE802154_ADDR_UNDEF		0xfffe

struct sockaddr_ieee802154 {
	sa_family_t family; /* AF_IEEE802154 */
	struct ieee802154_addr_sa addr;
};

/* get/setsockopt */
#define SOL_IEEE802154	0

#define WPAN_WANTACK		0
#define WPAN_SECURITY		1
#define WPAN_SECURITY_LEVEL	2

#define WPAN_SECURITY_DEFAULT	0
#define WPAN_SECURITY_OFF	1
#define WPAN_SECURITY_ON	2

#define WPAN_SECURITY_LEVEL_DEFAULT	(-1)

#endif /* _AF_IEEE802154_H */

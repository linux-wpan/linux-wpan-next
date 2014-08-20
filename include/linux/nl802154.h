/*
 * nl802154.h
 *
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

#ifndef NL802154_H
#define NL802154_H

enum nl802154_iftype {
	NL802154_IFTYPE_UNSPEC = -1,

	NL802154_IFTYPE_NODE,
	NL802154_IFTYPE_MONITOR,
	NL802154_IFTYPE_COORD,

	/* keep last */
	NUM_NL802154_IFTYPES,
	NL802154_IFTYPE_MAX = NUM_NL802154_IFTYPES - 1
};

#endif /* NL802154_H */

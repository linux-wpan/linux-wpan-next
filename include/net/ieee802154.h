/*
 * IEEE802.15.4-2003 specification
 *
 * Copyright (C) 2007, 2008 Siemens AG
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
 * Pavel Smolenskiy <pavel.smolenskiy@gmail.com>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Maxim Osipov <maxim.osipov@siemens.com>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#ifndef NET_IEEE802154_H
#define NET_IEEE802154_H

#include <linux/random.h>

#define IEEE802154_MTU				127
#define IEEE802154_MIN_FRAME_LEN		5
#define IEEE802154_FCS_LEN			2

#define IEEE802154_PAN_ID_BROADCAST		0xffff
#define IEEE802154_ADDR_SHORT_BROADCAST		0xffff

#define IEEE802154_ADDR_EXTENDED_LEN		8
#define IEEE802154_ADDR_SHORT_LEN		2
#define IEEE802154_PAN_ID_LEN			2

#define IEEE802154_MAX_PAGE		31
#define IEEE802154_MAX_CHANNEL		26

#define IEEE802154_FC_TYPE_BEACON	0x0	/* Frame is beacon */
#define	IEEE802154_FC_TYPE_DATA		0x1	/* Frame is data */
#define IEEE802154_FC_TYPE_ACK		0x2	/* Frame is acknowledgment */
#define IEEE802154_FC_TYPE_MAC_CMD	0x3	/* Frame is MAC command */

#define IEEE802154_FC_TYPE_SHIFT		0
#define IEEE802154_FC_TYPE_MASK		((1 << 3) - 1)
#define IEEE802154_FC_TYPE(x)		((x & IEEE802154_FC_TYPE_MASK) >> IEEE802154_FC_TYPE_SHIFT)
#define IEEE802154_FC_SET_TYPE(v, x)	do {	\
	v = (((v) & ~IEEE802154_FC_TYPE_MASK) | \
	    (((x) << IEEE802154_FC_TYPE_SHIFT) & IEEE802154_FC_TYPE_MASK)); \
	} while (0)

#define IEEE802154_FC_SECEN_SHIFT	3
#define IEEE802154_FC_SECEN		(1 << IEEE802154_FC_SECEN_SHIFT)
#define IEEE802154_FC_FRPEND_SHIFT	4
#define IEEE802154_FC_FRPEND		(1 << IEEE802154_FC_FRPEND_SHIFT)
#define IEEE802154_FC_ACK_REQ_SHIFT	5
#define IEEE802154_FC_ACK_REQ		(1 << IEEE802154_FC_ACK_REQ_SHIFT)
#define IEEE802154_FC_INTRA_PAN_SHIFT	6
#define IEEE802154_FC_INTRA_PAN		(1 << IEEE802154_FC_INTRA_PAN_SHIFT)

#define IEEE802154_FC_SAMODE_SHIFT	14
#define IEEE802154_FC_SAMODE_MASK	(3 << IEEE802154_FC_SAMODE_SHIFT)
#define IEEE802154_FC_DAMODE_SHIFT	10
#define IEEE802154_FC_DAMODE_MASK	(3 << IEEE802154_FC_DAMODE_SHIFT)

#define IEEE802154_FC_VERSION_SHIFT	12
#define IEEE802154_FC_VERSION_MASK	(3 << IEEE802154_FC_VERSION_SHIFT)
#define IEEE802154_FC_VERSION(x)	((x & IEEE802154_FC_VERSION_MASK) >> IEEE802154_FC_VERSION_SHIFT)

#define IEEE802154_FC_SAMODE(x)		\
	(((x) & IEEE802154_FC_SAMODE_MASK) >> IEEE802154_FC_SAMODE_SHIFT)

#define IEEE802154_FC_DAMODE(x)		\
	(((x) & IEEE802154_FC_DAMODE_MASK) >> IEEE802154_FC_DAMODE_SHIFT)

#define IEEE802154_SCF_SECLEVEL_MASK		7
#define IEEE802154_SCF_SECLEVEL_SHIFT		0
#define IEEE802154_SCF_SECLEVEL(x)		(x & IEEE802154_SCF_SECLEVEL_MASK)
#define IEEE802154_SCF_KEY_ID_MODE_SHIFT	3
#define IEEE802154_SCF_KEY_ID_MODE_MASK		(3 << IEEE802154_SCF_KEY_ID_MODE_SHIFT)
#define IEEE802154_SCF_KEY_ID_MODE(x)		\
	((x & IEEE802154_SCF_KEY_ID_MODE_MASK) >> IEEE802154_SCF_KEY_ID_MODE_SHIFT)

#define IEEE802154_SCF_KEY_IMPLICIT		0
#define IEEE802154_SCF_KEY_INDEX		1
#define IEEE802154_SCF_KEY_SHORT_INDEX		2
#define IEEE802154_SCF_KEY_HW_INDEX		3

#define IEEE802154_SCF_SECLEVEL_NONE		0
#define IEEE802154_SCF_SECLEVEL_MIC32		1
#define IEEE802154_SCF_SECLEVEL_MIC64		2
#define IEEE802154_SCF_SECLEVEL_MIC128		3
#define IEEE802154_SCF_SECLEVEL_ENC		4
#define IEEE802154_SCF_SECLEVEL_ENC_MIC32	5
#define IEEE802154_SCF_SECLEVEL_ENC_MIC64	6
#define IEEE802154_SCF_SECLEVEL_ENC_MIC128	7

/* MAC's Command Frames Identifiers */
#define IEEE802154_CMD_ASSOCIATION_REQ		0x01
#define IEEE802154_CMD_ASSOCIATION_RESP		0x02
#define IEEE802154_CMD_DISASSOCIATION_NOTIFY	0x03
#define IEEE802154_CMD_DATA_REQ			0x04
#define IEEE802154_CMD_PANID_CONFLICT_NOTIFY	0x05
#define IEEE802154_CMD_ORPHAN_NOTIFY		0x06
#define IEEE802154_CMD_BEACON_REQ		0x07
#define IEEE802154_CMD_COORD_REALIGN_NOTIFY	0x08
#define IEEE802154_CMD_GTS_REQ			0x09

/* frame control handling */
#define IEEE802154_FCTL_FTYPE                   0x0003
#define IEEE802154_FCTL_SEC                     0x0008
#define IEEE802154_FCTL_FP                      0x0010
#define IEEE802154_FCTL_AR                      0x0020
#define IEEE802154_FCTL_INTRA                   0x0040
#define IEEE802154_FCTL_DADDR                   0x0c00
#define IEEE802154_FCTL_VERS                    0x3000
#define IEEE802154_FCTL_SADDR                   0xc000

#define IEEE802154_FCTL_ADDR			(IEEE802154_FCTL_DADDR | \
						 IEEE802154_FCTL_SADDR)

#define IEEE802154_FCTL_VERS_RESERVED		0x2000

#define IEEE802154_FCTL_ADDR_NONE		0x0000

#define IEEE802154_FCTL_DADDR_RESERVED          0x0400
#define IEEE802154_FCTL_DADDR_SHORT             0x0800
#define IEEE802154_FCTL_DADDR_EXTENDED          0x0c00

#define IEEE802154_FCTL_SADDR_RESERVED          0x4000
#define IEEE802154_FCTL_SADDR_SHORT             0x8000
#define IEEE802154_FCTL_SADDR_EXTENDED          0xc000

#define IEEE802154_FTYPE_BEACON                 0x0000
#define IEEE802154_FTYPE_DATA                   0x0001
#define IEEE802154_FTYPE_ACK                    0x0002
#define IEEE802154_FTYPE_CMD                    0x0003

/* reserved is 100-111, so if 0x0004 bit is set */
#define IEEE802154_FTYPE_RESERVED               0x0004

struct ieee802154_addr {
	__le16 mode;
	__le16 pan_id;
	union {
		__le16 short_addr;
		__le64 extended_addr;
	};
};

struct ieee802154_hdr {
	__le16 frame_control;
	u8 sequence_number;
	u8 payload[0];
} __attribute__ ((packed));

/* Clear channel assesment (CCA) modes */
enum ieee802154_cca_modes {
	IEEE802154_CCA_ENERGY		= 1,
	IEEE802154_CCA_CARRIER		= 2,
	IEEE802154_CCA_ENERGY_CARRIER	= 3,
	IEEE802154_CCA_ALOHA		= 4,
	IEEE802154_CCA_UWB_SHR		= 5,
	IEEE802154_CCA_UWB_MULTIPEXED	= 6,
};

/**
 * ieee802154_is_beacon - check if type is IEEE802154_FTYPE_BEACON
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_beacon(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE802154_FCTL_FTYPE)) ==
		cpu_to_le16(IEEE802154_FTYPE_BEACON);
}

/**
 * ieee802154_is_data - check if type is IEEE802154_FTYPE_DATA
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_data(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_FTYPE)) ==
                cpu_to_le16(IEEE802154_FTYPE_DATA);
}

/**
 * ieee802154_is_ack - check if type is IEEE802154_FTYPE_ACK
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_ack(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_FTYPE)) ==
                cpu_to_le16(IEEE802154_FTYPE_ACK);
}

/**
 * ieee802154_is_cmd - check if type is IEEE802154_FTYPE_CMD
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_cmd(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_FTYPE)) ==
                cpu_to_le16(IEEE802154_FTYPE_CMD);
}

/**
 * ieee802154_is_reserved - check if bit IEEE802154_FTYPE_RESERVED is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_reserved(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_FTYPE)) &
                cpu_to_le16(IEEE802154_FTYPE_RESERVED);
}

/**
 * ieee802154_is_intra_pan - check if source pan id is compressed
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_intra_pan(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE802154_FCTL_INTRA));
}

/**
 * ieee802154_daddr_mode - get daddr bits from fc
 * @fc: frame control bytes in little-endian byteorder
 */
static inline __le16 ieee802154_daddr_mode(__le16 fc)
{
        return fc & cpu_to_le16(IEEE802154_FCTL_DADDR);
}

/**
 * ieee802154_is_vers_reserved - check if bit IEEE802154_FCTL_VERS_RESERVED is set
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_vers_reserved(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_VERS)) &
                cpu_to_le16(IEEE802154_FCTL_VERS_RESERVED);
}

/**
 * ieee802154_is_daddr_none - check if daddr mode is none
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_daddr_none(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_DADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_ADDR_NONE);
}

/**
 * ieee802154_is_daddr_reserved - check if daddr mode is reserved
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_daddr_reserved(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE802154_FCTL_DADDR)) ==
		cpu_to_le16(IEEE802154_FCTL_DADDR_RESERVED);
}

/**
 * ieee802154_is_daddr_short - check if daddr mode is short
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_daddr_short(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_DADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT);
}

/**
 * ieee802154_is_daddr_extended - check if daddr mode is extended
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_daddr_extended(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_DADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED);
}

static inline size_t ieee802154_daddr_len(__le16 fc)
{
	switch (fc & cpu_to_le16(IEEE802154_FCTL_DADDR)) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		return IEEE802154_ADDR_EXTENDED_LEN;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		return IEEE802154_ADDR_SHORT_LEN;
	default:
		/* useful to check none here? should already check by _is_none 
		 * functions.
		 */
		BUG();
	}
}

/**
 * ieee802154_xisdaddr_mode - get saddr bits from fc
 * @fc: frame control bytes in little-endian byteorder
 */
static inline __le16 ieee802154_saddr_mode(__le16 fc)
{
        return fc & cpu_to_le16(IEEE802154_FCTL_SADDR);
}

/**
 * ieee802154_is_saddr_none - check if saddr mode is none
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_saddr_none(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_SADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_ADDR_NONE);
}

/**
 * ieee802154_is_saddr_reserved - check if saddr mode is reserved
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_saddr_reserved(__le16 fc)
{
	return (fc & cpu_to_le16(IEEE802154_FCTL_SADDR)) ==
		cpu_to_le16(IEEE802154_FCTL_SADDR_RESERVED);
}

/**
 * ieee802154_is_saddr_short - check if saddr mode is short
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_saddr_short(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_SADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT);
}

/**
 * ieee802154_is_saddr_short - check if saddr mode is short
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_saddr_extended(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_SADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED);
}

static inline size_t ieee802154_saddr_len(__le16 fc)
{
	switch (fc & cpu_to_le16(IEEE802154_FCTL_SADDR)) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		return IEEE802154_ADDR_EXTENDED_LEN;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		return IEEE802154_ADDR_SHORT_LEN;
	default:
		/* reserved and none should never happen */
		BUG();
	}
}

static inline struct ieee802154_addr
ieee802154_hdr_daddr(struct ieee802154_hdr *hdr)
{
	struct ieee802154_addr addr = {};
	unsigned char *payload = hdr->payload;

	addr.mode = ieee802154_daddr_mode(hdr->frame_control);
	
	/* pan_id only available on non none address mode */
	switch (addr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		memcpy(&addr.pan_id, payload, IEEE802154_PAN_ID_LEN);
		payload += IEEE802154_PAN_ID_LEN;

		memcpy(&addr.extended_addr, payload,
		       IEEE802154_ADDR_EXTENDED_LEN);
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		memcpy(&addr.pan_id, payload, IEEE802154_PAN_ID_LEN);
		payload += IEEE802154_PAN_ID_LEN;

		memcpy(&addr.short_addr, payload, IEEE802154_ADDR_SHORT_LEN);
		break;
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		break;
	default:
		/* reserved should never happen */
		BUG();
	}

	return addr;
}

static inline struct ieee802154_addr
ieee802154_hdr_saddr(struct ieee802154_hdr *hdr)
{
	struct ieee802154_addr addr = {};
	unsigned char *payload = hdr->payload;

	addr.mode = ieee802154_saddr_mode(hdr->frame_control);

	/* pan_id only available on non none address mode */
	switch (ieee802154_daddr_mode(hdr->frame_control)) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		if (ieee802154_is_intra_pan(hdr->frame_control))
			memcpy(&addr.pan_id, payload, IEEE802154_PAN_ID_LEN);

		payload += IEEE802154_PAN_ID_LEN +
			   IEEE802154_ADDR_EXTENDED_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		if (ieee802154_is_intra_pan(hdr->frame_control))
			memcpy(&addr.pan_id, payload, IEEE802154_PAN_ID_LEN);

		payload += IEEE802154_PAN_ID_LEN +
			   IEEE802154_ADDR_SHORT_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		break;
	default:
		/* reserved should never happen */
		BUG();
	}

	/* pan_id only available on non none address mode */
	switch (addr.mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		if (!ieee802154_is_intra_pan(hdr->frame_control)) {
			memcpy(&addr.pan_id, payload, IEEE802154_PAN_ID_LEN);
			payload += IEEE802154_PAN_ID_LEN;
		}

		memcpy(&addr.extended_addr, payload,
		       IEEE802154_ADDR_EXTENDED_LEN);
		break;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		if (!ieee802154_is_intra_pan(hdr->frame_control)) {
			memcpy(&addr.pan_id, payload, IEEE802154_PAN_ID_LEN);
			payload += IEEE802154_PAN_ID_LEN;
		}

		memcpy(&addr.short_addr, payload, IEEE802154_ADDR_SHORT_LEN);
		break;
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		break;
	default:
		/* reserved should never happen */
		BUG();
	}

	return addr;
}

static inline bool ieee802154_is_valid_frame_len(const u8 len)
{
	if (len > IEEE802154_MTU || len < IEEE802154_MIN_FRAME_LEN)
		return false;

	return true;
}

static inline bool ieee802154_is_valid_extended_addr(const __le64 addr)
{
	static const u8 zero[IEEE802154_ADDR_EXTENDED_LEN] = { };
	static const u8 full[IEEE802154_ADDR_EXTENDED_LEN] = { 0xff, 0xff,
							       0xff, 0xff,
							       0xff, 0xff,
							       0xff, 0xff };

	return memcmp(&addr, full, IEEE802154_ADDR_EXTENDED_LEN) ||
	       memcmp(&addr, zero, IEEE802154_ADDR_EXTENDED_LEN);
}

static inline __le64 ieee802154_random_extended_addr(void)
{
	__le64 addr;

	get_random_bytes(&addr, IEEE802154_ADDR_EXTENDED_LEN);

	/* toggle some bit if we hit an invalid extended addr */
	if (!ieee802154_is_valid_extended_addr(addr))
		((u8 *)&addr)[IEEE802154_ADDR_EXTENDED_LEN - 1] ^= 1;

	return addr;
}

static inline bool ieee802154_is_pan_broadcast(const __le16 pan_id)
{
	if (pan_id == cpu_to_le16(IEEE802154_PAN_ID_BROADCAST))
		return true;

	return false;
}

/**
 * should only call with destination address */
static inline bool ieee802154_is_short_broadcast(const __le16 short_addr)
{
	if (short_addr == cpu_to_le16(IEEE802154_ADDR_SHORT_BROADCAST))
		return true;

	return false;
}

static inline bool ieee802154_is_valid_short_saddr(const __le16 short_saddr)
{
	return !ieee802154_is_short_broadcast(short_saddr);
}

/**
 * Generic function to validate 802.15.4 source address.
 */
static inline bool ieee802154_is_valid_saddr(struct ieee802154_addr *addr)
{
	if (unlikely(ieee802154_is_pan_broadcast(addr->pan_id)))
		return false;

	switch (addr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		return ieee802154_is_valid_extended_addr(addr->extended_addr);
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		return ieee802154_is_valid_short_saddr(addr->short_addr);
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		/* can be none on coordinators */
		return true;
	default:
		/* reserved should never happen */
		BUG();
		return false;
	}
}

/**
 * Generic function to validate 802.15.4 destination address.
 */
static inline bool ieee802154_is_valid_daddr(struct ieee802154_addr *addr)
{
	switch (addr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		return ieee802154_is_valid_extended_addr(addr->extended_addr);
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		return true;
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		/* should always available on frames with address modes */
		return false;
	default:
		/* reserved should never happen */
		BUG();
		return false;
	}
}

#endif

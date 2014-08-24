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
#define IEEE802154_MIN_FRAME_SIZE		5

#define IEEE802154_PAN_ID_BROADCAST		0xffff
#define IEEE802154_SHORT_ADDR_BROADCAST		0xffff

#define IEEE802154_EXTENDED_ADDR_LEN		8
#define IEEE802154_SHORT_ADDR_LEN		2
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

/* MAC footer size */
#define IEEE802154_MFR_SIZE	2 /* 2 octets */

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

#define IEEE802154_FCTL_DADDR_NONE              0x0000
#define IEEE802154_FCTL_DADDR_RESERVED          0x0400
#define IEEE802154_FCTL_DADDR_SHORT             0x0800
#define IEEE802154_FCTL_DADDR_EXTENDED          0x0c00

#define IEEE802154_FCTL_SADDR_NONE              0x0000
#define IEEE802154_FCTL_SADDR_RESERVED          0x4000
#define IEEE802154_FCTL_SADDR_SHORT             0x8000
#define IEEE802154_FCTL_SADDR_EXTENDED          0xc000

#define IEEE802154_FTYPE_BEACON                 0x0000
#define IEEE802154_FTYPE_DATA                   0x0001
#define IEEE802154_FTYPE_ACK                    0x0002
#define IEEE802154_FTYPE_CMD                    0x0003

/* reserved is 100-111, so if 0x0004 bit is set */
#define IEEE802154_FTYPE_RESERVED               0x0004

/* TODO remove the foo and ieee802154_addr struct */
union ieee802154_addr_foo {
	__le16 short_addr;
	__le64 extended_addr;
};

/* TODO remove the foo and ieee802154_hdr struct */
struct ieee802154_hdr_foo {
	__le16 frame_control;
	u8 sequence_number;
	u8 payload[0];
} __attribute__ ((packed));

struct ieee802154_hdr_data {
	__le16 frame_control;
	u8 sequence_number;
	__le16 dest_pan_id;
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
 * ieee802154_is_daddr_none - check if daddr mode is none
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_daddr_none(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_DADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_DADDR_NONE);
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

/**
 * ieee802154_is_saddr_none - check if saddr mode is none
 * @fc: frame control bytes in little-endian byteorder
 */
static inline int ieee802154_is_saddr_none(__le16 fc)
{
        return (fc & cpu_to_le16(IEEE802154_FCTL_SADDR)) ==
                cpu_to_le16(IEEE802154_FCTL_SADDR_NONE);
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

static inline union ieee802154_addr_foo *
ieee802154_hdr_data_dest_addr(struct ieee802154_hdr_data *hdr)
{
	return (union ieee802154_addr_foo *)hdr->payload;
}

static inline __le16 *
ieee802154_hdr_data_src_pan_id(struct ieee802154_hdr_data *hdr)
{
	if (ieee802154_is_intra_pan(hdr->frame_control))
		return (__le16 *)(&hdr->dest_pan_id);

	if (ieee802154_is_daddr_extended(hdr->frame_control))
		return (__le16 *)(hdr->payload + IEEE802154_EXTENDED_ADDR_LEN);
	else
		return (__le16 *)(hdr->payload + IEEE802154_SHORT_ADDR_LEN);
}

static inline union ieee802154_addr_foo *
ieee802154_hdr_data_src_addr(struct ieee802154_hdr_data *hdr)
{
	if (ieee802154_is_intra_pan(hdr->frame_control)) {
		if (ieee802154_is_daddr_extended(hdr->frame_control))
			return (union ieee802154_addr_foo *)
				(hdr->payload + IEEE802154_EXTENDED_ADDR_LEN);
		else
			return (union ieee802154_addr_foo *)
				(hdr->payload + IEEE802154_SHORT_ADDR_LEN);
	}

	return (union ieee802154_addr_foo *)
		(((u8 *)ieee802154_hdr_data_src_pan_id(hdr)) +
		 IEEE802154_PAN_ID_LEN);
}

/*
 * The return values of MAC operations
 */
enum {
	/*
	 * The requested operation was completed successfully.
	 * For a transmission request, this value indicates
	 * a successful transmission.
	 */
	IEEE802154_SUCCESS = 0x0,

	/* The beacon was lost following a synchronization request. */
	IEEE802154_BEACON_LOSS = 0xe0,
	/*
	 * A transmission could not take place due to activity on the
	 * channel, i.e., the CSMA-CA mechanism has failed.
	 */
	IEEE802154_CHNL_ACCESS_FAIL = 0xe1,
	/* The GTS request has been denied by the PAN coordinator. */
	IEEE802154_DENINED = 0xe2,
	/* The attempt to disable the transceiver has failed. */
	IEEE802154_DISABLE_TRX_FAIL = 0xe3,
	/*
	 * The received frame induces a failed security check according to
	 * the security suite.
	 */
	IEEE802154_FAILED_SECURITY_CHECK = 0xe4,
	/*
	 * The frame resulting from secure processing has a length that is
	 * greater than aMACMaxFrameSize.
	 */
	IEEE802154_FRAME_TOO_LONG = 0xe5,
	/*
	 * The requested GTS transmission failed because the specified GTS
	 * either did not have a transmit GTS direction or was not defined.
	 */
	IEEE802154_INVALID_GTS = 0xe6,
	/*
	 * A request to purge an MSDU from the transaction queue was made using
	 * an MSDU handle that was not found in the transaction table.
	 */
	IEEE802154_INVALID_HANDLE = 0xe7,
	/* A parameter in the primitive is out of the valid range.*/
	IEEE802154_INVALID_PARAMETER = 0xe8,
	/* No acknowledgment was received after aMaxFrameRetries. */
	IEEE802154_NO_ACK = 0xe9,
	/* A scan operation failed to find any network beacons.*/
	IEEE802154_NO_BEACON = 0xea,
	/* No response data were available following a request. */
	IEEE802154_NO_DATA = 0xeb,
	/* The operation failed because a short address was not allocated. */
	IEEE802154_NO_SHORT_ADDRESS = 0xec,
	/*
	 * A receiver enable request was unsuccessful because it could not be
	 * completed within the CAP.
	 */
	IEEE802154_OUT_OF_CAP = 0xed,
	/*
	 * A PAN identifier conflict has been detected and communicated to the
	 * PAN coordinator.
	 */
	IEEE802154_PANID_CONFLICT = 0xee,
	/* A coordinator realignment command has been received. */
	IEEE802154_REALIGMENT = 0xef,
	/* The transaction has expired and its information discarded. */
	IEEE802154_TRANSACTION_EXPIRED = 0xf0,
	/* There is no capacity to store the transaction. */
	IEEE802154_TRANSACTION_OVERFLOW = 0xf1,
	/*
	 * The transceiver was in the transmitter enabled state when the
	 * receiver was requested to be enabled.
	 */
	IEEE802154_TX_ACTIVE = 0xf2,
	/* The appropriate key is not available in the ACL. */
	IEEE802154_UNAVAILABLE_KEY = 0xf3,
	/*
	 * A SET/GET request was issued with the identifier of a PIB attribute
	 * that is not supported.
	 */
	IEEE802154_UNSUPPORTED_ATTR = 0xf4,
	/*
	 * A request to perform a scan operation failed because the MLME was
	 * in the process of performing a previously initiated scan operation.
	 */
	IEEE802154_SCAN_IN_PROGRESS = 0xfc,
};

static inline bool ieee802154_is_valid_frame_len(const u8 len)
{
	if (unlikely(len > IEEE802154_MTU || len < IEEE802154_MIN_FRAME_SIZE))
		return false;

	return true;
}

static inline bool ieee802154_is_valid_extended_addr(const __le64 *addr)
{
	static const u8 full[8] = { 0xff, 0xff, 0xff, 0xff,
				    0xff, 0xff, 0xff, 0xff };
	static const u8 zero[8] = { 0x00, 0x00, 0x00, 0x00,
				    0x00, 0x00, 0x00, 0x00 };

	return memcmp(addr, full, IEEE802154_EXTENDED_ADDR_LEN) ||
	       memcmp(addr, zero, IEEE802154_EXTENDED_ADDR_LEN);
}

static inline void ieee802154_random_extended_addr(__le64 *addr)
{
	get_random_bytes(addr, IEEE802154_EXTENDED_ADDR_LEN);

	/* toggle some bit if we hit an invalid extended addr */
	if (!ieee802154_is_valid_extended_addr(addr))
		((u8 *)addr)[IEEE802154_EXTENDED_ADDR_LEN - 1] ^= 0x01;
}

#endif

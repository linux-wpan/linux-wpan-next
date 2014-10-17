/*
 * Copyright (C) 2014 Fraunhofer ITWM
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
 * Written by:
 * Phoebe Buckheister <phoebe.buckheister@itwm.fraunhofer.de>
 */

#include <net/mac802154.h>
#include <net/ieee802154.h>
#include <net/cfg802154.h>

static int ieee802154_addr_len(const __le16 mode, const bool intra_pan)
{
	switch (mode) {
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		return 0;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		return IEEE802154_ADDR_SHORT_LEN +
		       IEEE802154_PAN_ID_LEN;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		return IEEE802154_ADDR_EXTENDED_LEN +
		       IEEE802154_PAN_ID_LEN;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		if (intra_pan)
			return IEEE802154_ADDR_SHORT_LEN;

		return IEEE802154_ADDR_SHORT_LEN +
		       IEEE802154_PAN_ID_LEN;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		if (intra_pan)
			return IEEE802154_ADDR_EXTENDED_LEN;

		return IEEE802154_ADDR_EXTENDED_LEN +
		       IEEE802154_PAN_ID_LEN;
	default:
		/* reserved should never happen */
		BUG();
		return -EINVAL;
	}
}

#if 0

static int ieee802154_sechdr_lengths[4] = {
	[IEEE802154_SCF_KEY_IMPLICIT] = 5,
	[IEEE802154_SCF_KEY_INDEX] = 6,
	[IEEE802154_SCF_KEY_SHORT_INDEX] = 10,
	[IEEE802154_SCF_KEY_HW_INDEX] = 14,
};


static int ieee802154_hdr_sechdr_len(const u8 sc)
{
	return ieee802154_sechdr_lengths[IEEE802154_SCF_KEY_ID_MODE(sc)];
}
#endif

static int ieee802154_hdr_minlen(const struct ieee802154_addr *daddr,
				 const struct ieee802154_addr *saddr,
				 const bool intra_pan)
{
	int dlen, slen;

	dlen = ieee802154_addr_len(daddr->mode, intra_pan);
	if (dlen < 0)
		return dlen;

	slen = ieee802154_addr_len(saddr->mode, intra_pan);
	if (slen < 0)
		return slen;

	return 3 + dlen + slen;
}

int ieee802154_max_payload(const struct ieee802154_addr *daddr,
			   const struct ieee802154_addr *saddr,
			   const bool intra_pan)
{
	int hlen = ieee802154_hdr_minlen(daddr, saddr, intra_pan);

	/* TODO security fixme */

	return IEEE802154_MTU - hlen - IEEE802154_FCS_LEN;
}
EXPORT_SYMBOL_GPL(ieee802154_max_payload);

int ieee802154_create_h_data(struct sk_buff *skb,
			     struct wpan_dev *wpan_dev,
			     const struct ieee802154_addr *daddr,
			     const struct ieee802154_addr *saddr,
			     const bool ack_req)
{
	unsigned char buf[MAC802154_FRAME_HARD_HEADER_LEN];
	struct ieee802154_hdr *hdr = (struct ieee802154_hdr *)buf;
	unsigned char *buf_ptr = buf + 3;
	__le16 fc = cpu_to_le16(IEEE802154_FTYPE_DATA);
#if 0
	struct ieee802154_sechdr hdr_sec;
#endif

	switch (daddr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_DADDR_EXTENDED):
		memcpy(buf_ptr, &daddr->pan_id, IEEE802154_PAN_ID_LEN);
		buf_ptr += IEEE802154_PAN_ID_LEN;

		memcpy(buf_ptr, &daddr->extended_addr, IEEE802154_ADDR_EXTENDED_LEN);
		buf_ptr += IEEE802154_ADDR_EXTENDED_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_DADDR_SHORT):
		memcpy(buf_ptr, &daddr->pan_id, IEEE802154_PAN_ID_LEN);
		buf_ptr += IEEE802154_PAN_ID_LEN;

		memcpy(buf_ptr, &daddr->short_addr, IEEE802154_ADDR_SHORT_LEN);
		buf_ptr += IEEE802154_ADDR_SHORT_LEN;
		break;
	default:
		/* reserved and none should never happen */
		return -EINVAL;
	}
	fc |= daddr->mode;

	switch (saddr->mode) {
	case cpu_to_le16(IEEE802154_FCTL_SADDR_EXTENDED):
		if (saddr->pan_id != daddr->pan_id) {
			memcpy(buf_ptr, &saddr->pan_id, IEEE802154_PAN_ID_LEN);
			buf_ptr += IEEE802154_PAN_ID_LEN;
		} else {
			fc |= cpu_to_le16(IEEE802154_FCTL_INTRA);
		}

		memcpy(buf_ptr, &saddr->extended_addr, IEEE802154_ADDR_EXTENDED_LEN);
		buf_ptr += IEEE802154_ADDR_EXTENDED_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_SADDR_SHORT):
		if (saddr->pan_id != daddr->pan_id) {
			memcpy(buf_ptr, &saddr->pan_id, IEEE802154_PAN_ID_LEN);
			buf_ptr += IEEE802154_PAN_ID_LEN;
		} else {
			fc |= cpu_to_le16(IEEE802154_FCTL_INTRA);
		}

		memcpy(buf_ptr, &saddr->short_addr, IEEE802154_ADDR_SHORT_LEN);
		buf_ptr += IEEE802154_ADDR_SHORT_LEN;
		break;
	case cpu_to_le16(IEEE802154_FCTL_ADDR_NONE):
		/* TODO special handling if wpan_dev is coord */
		break;
	default:
		/* reserved should never happen */
		return -EINVAL;
	}
	fc |= saddr->mode;

	if (ack_req)
		fc |= cpu_to_le16(IEEE802154_FCTL_AR);

#if 0
	/* TODO check mac pib if sec enabled */
	fc |= cpu_to_le16(IEEE802154_FCTL_SEC);
	fc |= cpu_to_le16(IEEE802154_FCTL_VERS_ONE);

	hdr_sec.level = wpan_dev->out_level;
	hdr_sec.key_id_mode = wpan_dev->out_key.mode;
	hdr_sec.key_id = wpan_dev->out_key.id;
	hdr_sec.frame_counter = cpu_to_le32(wpan_dev->frame_counter);

	memcpy(buf_ptr, &hdr_sec, 6);
	buf_ptr += 6;
#endif

	hdr->frame_control = fc;
	hdr->sequence_number = wpan_dev->dsn++;
	
	memcpy(skb_push(skb, (u16)(buf_ptr - buf)), buf, (u16)(buf_ptr - buf));
	
	skb_reset_mac_header(skb);
	skb->mac_len = (u16)(buf_ptr - buf);

	if (skb->len > IEEE802154_MTU - 2)
		return -EMSGSIZE;

	return 0;
}
EXPORT_SYMBOL_GPL(ieee802154_create_h_data);

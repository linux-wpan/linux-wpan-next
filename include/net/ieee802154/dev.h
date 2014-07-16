#ifndef __IEEE802154_DEV_H__
#define __IEEE802154_DEV_H__

#include <net/ipv6.h>
#include <net/ieee802154.h>

#include <linux/skbuff.h>

#define IEEE802154_RESERVED_SIZE	(sizeof(struct ipv6hdr) + \
					 sizeof(struct udphdr))

struct sk_buff *alloc_ieee802154_skb(void);

/**
 * valid_ieee802154_pdu_len - check if psdu len is in a valid range.
 * @len: psdu len inclusive MHR, payload and MFR
 */
static inline bool valid_ieee802154_psdu_len(const u8 len)
{
	if (unlikely(len > IEEE802154_MTU || len < IEEE802154_MIN_SIZE))
		return false;

	return true;
}

#endif /* __IEEE802154_DEV_H__ */

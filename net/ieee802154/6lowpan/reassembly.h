#ifndef __IEEE802154_6LOWPAN_REASSEMBLY_H__
#define __IEEE802154_6LOWPAN_REASSEMBLY_H__

#include <net/inet_frag.h>

#include "6lowpan_i.h"

struct lowpan_create_arg {
	__be16 tag;
	u16 d_size;
	const struct lowpan_addr *saddr;
	const struct lowpan_addr *daddr;
};

/* Equivalent of ipv4 struct ip
 */
struct lowpan_frag_queue {
	struct inet_frag_queue	q;

	__be16			tag;
	u16			d_size;
	struct lowpan_addr	saddr;
	struct lowpan_addr	daddr;
};

static inline u32 ieee802154_addr_hash(const struct lowpan_addr *a)
{
	/* byte ordering doesn't matter to create hash */
	switch (a->mode) {
	case IEEE802154_ADDR_LONG:
		return (((__force u64)a->u.extended) >> 32) ^
			(((__force u64)a->u.extended) & 0xffffffff);
	case IEEE802154_ADDR_SHORT:
		return (__force u32)(a->u.short_);
	default:
		return 0;
	}
}

int lowpan_frag_rcv(struct sk_buff *skb, const u8 frag_type,
		    const struct lowpan_addr_info *info);
void lowpan_net_frag_exit(void);
int lowpan_net_frag_init(void);

#endif /* __IEEE802154_6LOWPAN_REASSEMBLY_H__ */

#ifndef __IEEE802154_6LOWPAN_REASSEMBLY_H__
#define __IEEE802154_6LOWPAN_REASSEMBLY_H__

#include <net/inet_frag.h>

#include "6lowpan_i.h"

struct lowpan_create_arg {
	__be16 tag;
	u16 d_size;
	const union lowpan_addr_u *saddr;
	const union lowpan_addr_u *daddr;
};

/* Equivalent of ipv4 struct ip
 */
struct lowpan_frag_queue {
	struct inet_frag_queue	q;

	__be16			tag;
	u16			d_size;
	union lowpan_addr_u	saddr;
	union lowpan_addr_u	daddr;
};

static inline bool lowpan_addr_equal(const union lowpan_addr_u *daddr,
				     const union lowpan_addr_u *saddr)
{
	return !memcmp(daddr, saddr, sizeof(*daddr));
}

static inline u32 ieee802154_addr_hash(const union lowpan_addr_u *a)
{
	/* byte ordering doesn't matter to create hash, using big endian here.
	 * short address should have short address and rest of these bytes
	 * should be zero, so xor with that doesn't matter.
	 */
	return ((((__force u64)a->extended) >> 32) ^
		(((__force u64)a->extended) & 0xffffffff));
}

int lowpan_frag_rcv(struct sk_buff *skb, const u8 frag_type,
		    const struct lowpan_addr_info *info);
void lowpan_net_frag_exit(void);
int lowpan_net_frag_init(void);

#endif /* __IEEE802154_6LOWPAN_REASSEMBLY_H__ */

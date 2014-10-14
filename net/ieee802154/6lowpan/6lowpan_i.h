#ifndef __IEEE802154_6LOWPAN_I_H
#define __IEEE802154_6LOWPAN_I_H

#include <linux/list.h>
#include <linux/netdevice.h>

#include <net/ieee802154.h>

typedef unsigned __bitwise__ lowpan_rx_result;
#define RX_CONTINUE             ((__force lowpan_rx_result) 0u)
#define RX_DROP_UNUSABLE        ((__force lowpan_rx_result) 1u)
/* don't use 2u for monitor, it's the same like 80211 and 802154 */
#define RX_QUEUED               ((__force lowpan_rx_result) 3u)

#define LOWPAN_DISPATCH_FRAG_MASK	0xf8
#define LOWPAN_DISPATCH_FRAG1		0xc0
#define LOWPAN_DISPATCH_FRAGN		0xe0

#define LOWPAN_FRAG1_HEAD_SIZE		4
#define LOWPAN_FRAGN_HEAD_SIZE		5

#define LOWPAN_DISPATCH_HC1		0x42

/* don't save pan id, it's intra pan */
struct lowpan_addr {
	/* non converted address mode bits here 
	 * make this at first, improve memcmp on this struct */
	__le16 mode;
	union {
		/* IPv6 needs big endian here */
		__be64 extended_addr;
		__be16 short_addr;
	};
};

struct lowpan_addr_info {
	struct lowpan_addr daddr;
	struct lowpan_addr saddr;
};

/* private device info */
struct lowpan_dev_info {
	struct net_device	*wdev; /* real WPAN device ptr */
	u16			fragment_tag;
};

static inline struct
lowpan_dev_info *lowpan_dev_info(const struct net_device *dev)
{
	return netdev_priv(dev);
}

static inline u8 lowpan_get_frag_type(const u8 dispatch)
{
	return dispatch & LOWPAN_DISPATCH_FRAG_MASK;
}

static inline bool lowpan_is_frag(const u8 dispatch)
{
	const u8 tmp = lowpan_get_frag_type(dispatch);
	return tmp == LOWPAN_DISPATCH_FRAG1 || tmp == LOWPAN_DISPATCH_FRAGN;
}

int lowpan_header_create(struct sk_buff *skb, struct net_device *dev,
			 unsigned short type, const void *_daddr,
			 const void *_saddr, unsigned int len);
int ieee802154_max_payload(const struct ieee802154_addr *daddr,
			   const struct ieee802154_addr *saddr,
			   const bool intra_pan);
int ieee802154_create_h_data(struct sk_buff *skb,
                             struct wpan_dev *wpan_dev,
                             const struct ieee802154_addr *saddr,
                             const struct ieee802154_addr *daddr,
                             const bool ack_req);
netdev_tx_t lowpan_xmit(struct sk_buff *skb, struct net_device *dev);
void lowpan_init_rx(void);
void lowpan_cleanup_rx(void);

#endif /* __IEEE802154_6LOWPAN_I_H */

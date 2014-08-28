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

/* private device info */
struct lowpan_dev_info {
	struct net_device	*wdev; /* real WPAN device ptr */
	__be16			fragment_tag;
};

/* don't save pan id, it's intra pan */
struct lowpan_addr {
	/* non converted address mode bits here 
	 * make this at first, improve memcmp on this struct */
	__le16 mode;
	union {
		/* IPv6 needs big endian here */
		__be64 extended;
		__be16 short_;
	} addr;
};

static inline bool lowpan_addr_equal(const struct lowpan_addr *daddr,
				     const struct lowpan_addr *saddr)
{
	return !memcmp(daddr, saddr, sizeof(*daddr));
}

struct lowpan_addr_info {
	struct lowpan_addr daddr;
	struct lowpan_addr saddr;
};

static inline struct
lowpan_dev_info *lowpan_dev_info(const struct net_device *dev)
{
	return netdev_priv(dev);
}

int lowpan_header_create(struct sk_buff *skb, struct net_device *dev,
			 unsigned short type, const void *_daddr,
			 const void *_saddr, unsigned int len);
netdev_tx_t lowpan_xmit(struct sk_buff *skb, struct net_device *dev);
void lowpan_init_rx(void);
void lowpan_cleanup_rx(void);

#endif /* __IEEE802154_6LOWPAN_I_H */

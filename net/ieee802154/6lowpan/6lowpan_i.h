#ifndef __IEEE802154_6LOWPAN_I_H
#define __IEEE802154_6LOWPAN_I_H

#include <linux/list.h>
#include <linux/netdevice.h>

/* private device info */
struct lowpan_dev_info {
	struct net_device	*real_dev; /* real WPAN device ptr */
	__be16			fragment_tag;
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

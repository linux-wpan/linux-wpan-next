#ifndef __IEEE802154_6LOWPAN_I_H
#define __IEEE802154_6LOWPAN_I_H

#include <linux/list.h>
#include <linux/netdevice.h>

struct lowpan_dev_record {
	struct net_device *ldev;
	struct list_head list;
};

/* private device info */
struct lowpan_dev_info {
	struct net_device	*real_dev; /* real WPAN device ptr */
	struct mutex		dev_list_mtx; /* mutex for list ops */
	__be16			fragment_tag;
};

static inline struct
lowpan_dev_info *lowpan_dev_info(const struct net_device *dev)
{
	return netdev_priv(dev);
}

void lowpan_init_rx(void);
void lowpan_cleanup_rx(void);

#endif /* __IEEE802154_6LOWPAN_I_H */

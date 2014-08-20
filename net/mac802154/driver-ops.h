#ifndef __MAC802154_DRVIER_OPS
#define __MAC802154_DRIVER_OPS

#include <linux/types.h>

#include <net/mac802154.h>

#include "ieee802154_i.h"

static inline int
drv_xmit_async(struct ieee802154_local *local, struct sk_buff *skb)
{
	return local->ops->xmit_async(&local->hw, skb);
}

static inline int
drv_xmit_sync(struct ieee802154_local *local, struct sk_buff *skb)
{
	might_sleep();

	return local->ops->xmit_sync(&local->hw, skb);
}

static inline int drv_start(struct ieee802154_local *local)
{
	might_sleep();

	smp_mb();
	return local->ops->start(&local->hw);
}

static inline void drv_stop(struct ieee802154_local *local)
{
	might_sleep();

	local->ops->stop(&local->hw);

	/* sync away all work on the tasklet before clearing started */
	tasklet_disable(&local->tasklet);
	tasklet_enable(&local->tasklet);

	barrier();
}

static inline int drv_set_channel(struct ieee802154_local *local,
				  u8 page, u8 channel)
{
	might_sleep();

	return local->ops->set_channel(&local->hw, page, channel);
}

static inline int drv_set_pan_id(struct ieee802154_local *local,
				 const __le16 pan_id)
{
	struct ieee802154_hw_addr_filt filt;

	might_sleep();

	if (!local->ops->set_hw_addr_filt)
		return -EOPNOTSUPP;

	filt.pan_id = pan_id;

	return local->ops->set_hw_addr_filt(&local->hw, &filt,
					    IEEE802154_AFILT_PANID_CHANGED);
}

#endif /* __MAC802154_DRVIER_OPS */

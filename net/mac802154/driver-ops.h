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

static inline int drv_set_tx_power(struct ieee802154_local *local, s8 dbm)
{
	might_sleep();

	if (!(local->hw.flags & IEEE802154_HW_TXPOWER) ||
	    !local->ops->set_txpower)
		return -EOPNOTSUPP;

	return local->ops->set_txpower(&local->hw, dbm);
}

static inline int drv_set_cca_mode(struct ieee802154_local *local, u8 cca_mode)
{
	might_sleep();

	if (!(local->hw.flags & IEEE802154_HW_CCA_MODE) ||
	    !local->ops->set_cca_mode)
		return -EOPNOTSUPP;

	return local->ops->set_cca_mode(&local->hw, cca_mode);
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

static inline int drv_set_extended_addr(struct ieee802154_local *local,
					const __le64 extended_addr)
{
	struct ieee802154_hw_addr_filt filt;

	might_sleep();

	if (!local->ops->set_hw_addr_filt)
		return -EOPNOTSUPP;

	filt.ieee_addr = extended_addr;

	return local->ops->set_hw_addr_filt(&local->hw, &filt,
					    IEEE802154_AFILT_IEEEADDR_CHANGED);
}

static inline int drv_set_csma_params(struct ieee802154_local *local,
				      u8 min_be, u8 max_be,
				      u8 max_csma_backoffs)
{
	might_sleep();

	if (!(local->hw.flags & IEEE802154_HW_CSMA_PARAMS) ||
	    !local->ops->set_csma_params)
		return -EOPNOTSUPP;

	return local->ops->set_csma_params(&local->hw, min_be, max_be,
					   max_csma_backoffs);
}

#endif /* __MAC802154_DRVIER_OPS */

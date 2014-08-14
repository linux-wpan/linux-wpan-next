#ifndef __MAC802154_DRVIER_OPS
#define __MAC802154_DRIVER_OPS

#include <net/mac802154.h>

#include "ieee802154_i.h"

static inline int
drv_xmit(struct ieee802154_local *local, struct sk_buff *skb)
{
	return local->ops->xmit(&local->hw, skb);
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

#endif /* __MAC802154_DRVIER_OPS */

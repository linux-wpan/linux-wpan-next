#ifndef __NET_IEEE802154_CORE_H
#define __NET_IEEE802154_CORE_H

#include <net/ieee802154.h>
#include <net/cfg802154.h>

struct cfg802154_registered_device {
	const struct cfg802154_ops *ops;

	/* wpan_phy index, internal only */
	int wpan_phy_idx;

	/* must be last because of the way we do wpan_phy_priv(),
	 * and it should at least be aligned to NETDEV_ALIGN */
	struct wpan_phy wpan_phy __aligned(NETDEV_ALIGN);
};

#endif /* __NET_IEEE802154_CORE_H */

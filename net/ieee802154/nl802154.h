#ifndef __NET_WPAN_NL802154_H
#define __NET_WPAN_NL802154_H

#include "core.h"

int nl802154_init(void);
void nl802154_exit(void);
void nl802154_notify_wpan_phy(struct cfg802154_registered_device *rdev,
			      enum nl802154_commands cmd);

#endif /* __NET_WPAN_NL802154_H */

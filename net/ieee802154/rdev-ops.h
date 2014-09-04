#ifndef __CFG802154_RDEV_OPS
#define __CFG802154_RDEV_OPS

#include <net/cfg802154.h>

static inline struct wpan_dev *
rdev_add_virtual_intf(struct cfg802154_registered_device *rdev, char *name,
		      enum nl802154_iftype type)
{
	return rdev->ops->add_virtual_intf(&rdev->wpan_phy, name, type);
}

static inline int
rdev_del_virtual_intf(struct cfg802154_registered_device *rdev,
		      struct wpan_dev *wpan_dev)
{
	return rdev->ops->del_virtual_intf(&rdev->wpan_phy, wpan_dev);
}

static inline int
rdev_set_page(struct cfg802154_registered_device *rdev, u8 page)
{
	return rdev->ops->set_page(&rdev->wpan_phy, page);
}

static inline int
rdev_set_channel(struct cfg802154_registered_device *rdev, u8 channel)
{
	return rdev->ops->set_channel(&rdev->wpan_phy, channel);
}

static inline int
rdev_set_tx_power(struct cfg802154_registered_device *rdev, const s8 dbm)
{
	return rdev->ops->set_tx_power(&rdev->wpan_phy, dbm);
}

static inline int
rdev_set_cca_mode(struct cfg802154_registered_device *rdev, const u8 cca_mode,
		  const u8 cca_mode3_and)
{
	return rdev->ops->set_cca_mode(&rdev->wpan_phy, cca_mode, cca_mode3_and);
}

static inline int
rdev_set_pan_id(struct cfg802154_registered_device *rdev,
		struct wpan_dev *wpan_dev, u16 pan_id)
{
	return rdev->ops->set_pan_id(&rdev->wpan_phy, wpan_dev, pan_id);
}

static inline int
rdev_set_short_addr(struct cfg802154_registered_device *rdev,
		    struct wpan_dev *wpan_dev, u16 short_addr)
{
	return rdev->ops->set_short_addr(&rdev->wpan_phy, wpan_dev, short_addr);
}

static inline int
rdev_set_max_frame_retries(struct cfg802154_registered_device *rdev,
			   struct wpan_dev *wpan_dev,
			   const s8 max_frame_retries)
{
	return rdev->ops->set_max_frame_retries(&rdev->wpan_phy, wpan_dev,
						max_frame_retries);
}

static inline int
rdev_set_max_be(struct cfg802154_registered_device *rdev,
		struct wpan_dev *wpan_dev,
		const u8 max_be)
{
	return rdev->ops->set_max_be(&rdev->wpan_phy, wpan_dev, max_be);
}

static inline int
rdev_set_max_csma_backoffs(struct cfg802154_registered_device *rdev,
			   struct wpan_dev *wpan_dev,
			   const u8 max_csma_backoffs)
{
	return rdev->ops->set_max_csma_backoffs(&rdev->wpan_phy, wpan_dev,
						max_csma_backoffs);
}

static inline int
rdev_set_min_be(struct cfg802154_registered_device *rdev,
		struct wpan_dev *wpan_dev,
		const u8 min_be)
{
	return rdev->ops->set_min_be(&rdev->wpan_phy, wpan_dev, min_be);
}

#endif /* __CFG802154_RDEV_OPS */

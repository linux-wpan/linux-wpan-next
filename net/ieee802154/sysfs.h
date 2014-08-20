#ifndef __WPAN_SYSFS_H
#define __WPAN_SYSFS_H

int wpan_phy_sysfs_init(void);
void wpan_phy_sysfs_exit(void);

extern struct class ieee802154_class;

#endif /* __WPAN_SYSFS_H */


#include <linux/nl802154.h>
#include <linux/rtnetlink.h>

#include <net/cfg802154.h>
#include <net/genetlink.h>
#include <net/mac802154.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "core.h"
#include "rdev-ops.h"

static int nl802154_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
			     struct genl_info *info);

static void nl802154_post_doit(const struct genl_ops *ops, struct sk_buff *skb,
			       struct genl_info *info);

/* the netlink family */
static struct genl_family nl802154_fam = {
	.id = GENL_ID_GENERATE,			/* don't bother with a hardcoded ID */
	.name = NL802154_GENL_NAME,		/* have users key off the name instead */
	.hdrsize = 0,				/* no private header */
	.version = 1,				/* no particular meaning now */
	.maxattr = NL802154_ATTR_MAX,
	.netnsok = true,
	.pre_doit = nl802154_pre_doit,
	.post_doit = nl802154_post_doit,
};

/* multicast groups */
enum nl802154_multicast_groups {
	NL802154_MCGRP_CONFIG,
};

static const struct genl_multicast_group nl802154_mcgrps[] = {
	[NL802154_MCGRP_CONFIG] = { .name = "config", },
};

/* returns ERR_PTR values */
static struct wpan_dev *
__cfg802154_wpan_dev_from_attrs(struct net *netns, struct nlattr **attrs)
{
	struct cfg802154_registered_device *rdev;
	struct wpan_dev *result = NULL;
	bool have_ifidx = attrs[NL802154_ATTR_IFINDEX];
	bool have_wpan_dev_id = attrs[NL802154_ATTR_WPAN_DEV];
	u64 wpan_dev_id;
	int wpan_phy_idx = -1;
	int ifidx = -1;

	ASSERT_RTNL();

	if (!have_ifidx && !have_wpan_dev_id)
		return ERR_PTR(-EINVAL);

	if (have_ifidx)
		ifidx = nla_get_u32(attrs[NL802154_ATTR_IFINDEX]);
	if (have_wpan_dev_id) {
		wpan_dev_id = nla_get_u64(attrs[NL802154_ATTR_WPAN_DEV]);
		wpan_phy_idx = wpan_dev_id >> 32;
	}

	list_for_each_entry(rdev, &cfg802154_rdev_list, list) {
                struct wpan_dev *wpan_dev;

                if (wpan_phy_net(&rdev->wpan_phy) != netns)
                        continue;

                if (have_wpan_dev_id && rdev->wpan_phy_idx != wpan_phy_idx)
                        continue;

                list_for_each_entry(wpan_dev, &rdev->wpan_dev_list, list) {
                        if (have_ifidx && wpan_dev->netdev &&
                            wpan_dev->netdev->ifindex == ifidx) {
                                result = wpan_dev;
                                break;
                        }
                        if (have_wpan_dev_id && wpan_dev->identifier == (u32)wpan_dev_id) {
                                result = wpan_dev;
                                break;
                        }
                }

                if (result)
                        break;
	}

	if (result)
		return result;

	printk(KERN_INFO "LALA NODEV\n"); 

	return ERR_PTR(-ENODEV);	
}

static struct cfg802154_registered_device *
__cfg802154_rdev_from_attrs(struct net *netns, struct nlattr **attrs)
{
	struct cfg802154_registered_device *rdev = NULL, *tmp;
	struct net_device *netdev;

	ASSERT_RTNL();

	if (!attrs[NL802154_ATTR_WPAN_PHY] &&
	    !attrs[NL802154_ATTR_IFINDEX] &&
	    !attrs[NL802154_ATTR_WPAN_DEV])
		return ERR_PTR(-EINVAL);

	if (attrs[NL802154_ATTR_WPAN_PHY])
		rdev = cfg802154_rdev_by_wpan_phy_idx(
				nla_get_u32(attrs[NL802154_ATTR_WPAN_PHY]));

	if (attrs[NL802154_ATTR_WPAN_DEV]) {
		u64 wpan_dev_id = nla_get_u64(attrs[NL802154_ATTR_WPAN_DEV]);
		struct wpan_dev *wpan_dev;
		bool found = false;

		tmp = cfg802154_rdev_by_wpan_phy_idx(wpan_dev_id >> 32);
		if (tmp) {
			/* make sure wpan_dev exists */
			list_for_each_entry(wpan_dev, &tmp->wpan_dev_list, list) {
				if (wpan_dev->identifier != (u32)wpan_dev_id)
					continue;
				found = true;
				break;
			}

			if (!found)
				tmp = NULL;

			if (rdev && tmp != rdev)
				return ERR_PTR(-EINVAL);
			rdev = tmp;
		}
	}

	if (attrs[NL802154_ATTR_IFINDEX]) {
		int ifindex = nla_get_u32(attrs[NL802154_ATTR_IFINDEX]);
		netdev = __dev_get_by_index(netns, ifindex);
		if (netdev) {
			if (netdev->ieee802154_ptr)
				tmp = wpan_phy_to_rdev(
						netdev->ieee802154_ptr->wpan_phy);
			else
				tmp = NULL;

			/* not wireless device -- return error */
			if (!tmp)
				return ERR_PTR(-EINVAL);

			/* mismatch -- return error */
			if (rdev && tmp != rdev)
				return ERR_PTR(-EINVAL);

			rdev = tmp;
		}
	}

	if (!rdev)
		return ERR_PTR(-ENODEV);

	if (netns != wpan_phy_net(&rdev->wpan_phy))
		return ERR_PTR(-ENODEV);

	return rdev;
}

/* This function returns a pointer to the driver
 * that the genl_info item that is passed refers to.
 *
 * The result of this can be a PTR_ERR and hence must
 * be checked with IS_ERR() for errors.
 */
static struct cfg802154_registered_device *
cfg802154_get_dev_from_info(struct net *netns, struct genl_info *info)
{
	return __cfg802154_rdev_from_attrs(netns, info->attrs);
}

/* policy for the attributes */
static const struct nla_policy nl802154_policy[NL802154_ATTR_MAX+1] = {
	[NL802154_ATTR_WPAN_PHY] = { .type = NLA_U32 },
	[NL802154_ATTR_WPAN_PHY_NAME] = { .type = NLA_NUL_STRING,
					  .len = 20-1 },

	[NL802154_ATTR_IFINDEX] = { .type = NLA_U32 },
	[NL802154_ATTR_IFTYPE] = { .type = NLA_U32 },
	[NL802154_ATTR_IFNAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ-1 },

	[NL802154_ATTR_WPAN_DEV] = { .type = NLA_U64 },

	[NL802154_ATTR_IFACE_SOCKET_OWNER] = { .type = NLA_FLAG },

	[NL802154_ATTR_PAGE] = { .type = NLA_U8, },
	[NL802154_ATTR_CHANNEL] = { .type = NLA_U8, },

	[NL802154_ATTR_TX_POWER] = { .type = NLA_S8, },

	[NL802154_ATTR_CCA_MODE] = { .type = NLA_U8, },

	[NL802154_ATTR_PAN_ID] = { .type = NLA_U16, },

	[NL802154_ATTR_MAX_FRAME_RETRIES] = { .type = NLA_S8, },

	[NL802154_ATTR_MAX_BE] = { .type = NLA_U8, },
	[NL802154_ATTR_MAX_CSMA_BACKOFFS] = { .type = NLA_U8, },
	[NL802154_ATTR_MIN_BE] = { .type = NLA_U8, },
};

/* message building helper */
static inline void *nl802154hdr_put(struct sk_buff *skb, u32 portid, u32 seq,
				    int flags, u8 cmd)
{
	/* since there is no private header just add the generic one */
	return genlmsg_put(skb, portid, seq, &nl802154_fam, flags, cmd);
}

struct nl802154_dump_wpan_phy_state {
	s64 filter_wpan_phy;
	long start;
	long split_start, band_start, chan_start;
	bool split;
};

static int nl802154_send_wpan_phy(struct cfg802154_registered_device *rdev,
				  enum nl802154_commands cmd,
				  struct sk_buff *msg, u32 portid, u32 seq,
				  int flags,
				  struct nl802154_dump_wpan_phy_state *state)
{
	return -ENOTSUPP;
}

static int nl802154_new_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev;
	struct sk_buff *msg;
	enum nl802154_iftype type = NL802154_IFTYPE_UNSPEC;

	/* to avoid failing a new interface creation due to pending removal */
	cfg802154_destroy_ifaces(rdev);

	if (!info->attrs[NL802154_ATTR_IFNAME])
		return -EINVAL;

	if (info->attrs[NL802154_ATTR_IFTYPE]) {
		type = nla_get_u32(info->attrs[NL802154_ATTR_IFTYPE]);
		if (type > NL802154_IFTYPE_MAX)
			return -EINVAL;
	}

	if (!rdev->ops->add_virtual_intf)
		return -EOPNOTSUPP;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	wpan_dev = rdev_add_virtual_intf(rdev,
					 nla_data(info->attrs[NL802154_ATTR_IFNAME]),
					 type);
	if (IS_ERR(wpan_dev)) {
		nlmsg_free(msg);
		return PTR_ERR(wpan_dev);
	}

	if (info->attrs[NL802154_ATTR_IFACE_SOCKET_OWNER])
		wpan_dev->owner_nlportid = info->snd_portid;

	return genlmsg_reply(msg, info);
}

static int nl802154_del_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];

	if (!rdev->ops->del_virtual_intf)
		return -EOPNOTSUPP;

	/*
	 * If we remove a wpan device without a netdev then clear
	 * user_ptr[1] so that nl802154_post_doit won't dereference it
	 * to check if it needs to do dev_put(). Otherwise it crashes
	 * since the wpan_dev has been freed, unlike with a netdev where
	 * we need the dev_put() for the netdev to really be freed.
	 */
	if (!wpan_dev->netdev)
		info->user_ptr[1] = NULL;

	return rdev_del_virtual_intf(rdev, wpan_dev);
}

static int nl802154_set_page(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	u8 page = 0;

	if (!info->attrs[NL802154_ATTR_PAGE])
		return -EINVAL;

	page = nla_get_u8(info->attrs[NL802154_ATTR_PAGE]);
	if (page > IEEE802154_MAX_PAGE)
		return -EINVAL;

	return rdev_set_page(rdev, page);
}

static int nl802154_set_channel(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	u8 channel;

	if (!info->attrs[NL802154_ATTR_CHANNEL])
		return -EINVAL;

	channel = nla_get_u8(info->attrs[NL802154_ATTR_CHANNEL]);
	if (channel > IEEE802154_MAX_CHANNEL)
		return -EINVAL;

	return rdev_set_channel(rdev, channel);
}

static int nl802154_set_tx_power(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	u8 tx_power;

	if (!info->attrs[NL802154_ATTR_TX_POWER])
		return -EINVAL;

	tx_power = nla_get_s8(info->attrs[NL802154_ATTR_TX_POWER]);

	return rdev_set_tx_power(rdev, tx_power);
}

static int nl802154_set_cca_mode(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	u8 cca_mode;

	if (info->attrs[NL802154_ATTR_CCA_MODE])
		return -EINVAL;
	
	cca_mode = nla_get_u8(info->attrs[NL802154_ATTR_CCA_MODE]);
	if (cca_mode < 1 || cca_mode > 6)
		return -EINVAL;

	return rdev_set_cca_mode(rdev, cca_mode);
}

static int nl802154_set_pan_id(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];
	u16 pan_id;

	if (!info->attrs[NL802154_ATTR_PAN_ID])
		return -EINVAL;

	pan_id = nla_get_u16(info->attrs[NL802154_ATTR_PAN_ID]);
	if (pan_id == IEEE802154_PAN_ID_BROADCAST)
		return -EINVAL;

	return rdev_set_pan_id(rdev, wpan_dev, pan_id);
}

static int nl802154_set_max_frame_retries(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];
	s8 max_frame_retries = -1;

	if (!info->attrs[NL802154_ATTR_MAX_FRAME_RETRIES])
		return -EINVAL;


	max_frame_retries = nla_get_s8(
			info->attrs[NL802154_ATTR_MAX_FRAME_RETRIES]);
	if (max_frame_retries < -1 || max_frame_retries > 7)
		return -EINVAL;

	return rdev_set_max_frame_retries(rdev, wpan_dev, max_frame_retries);
}

static int nl802154_set_max_be(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];
	u8 max_be;

	if (!info->attrs[NL802154_ATTR_MAX_BE])
		return -EINVAL;

	max_be = nla_get_u8(info->attrs[NL802154_ATTR_MAX_BE]);
	if (max_be < 3 || max_be > 8)
		return -EINVAL;

	/* check if violate min_be condition */
	if (wpan_dev->min_be > max_be)
		return -EINVAL;

	return rdev_set_max_be(rdev, wpan_dev, max_be);
}

static int nl802154_set_max_csma_backoffs(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];
	u8 max_csma_backoffs;

	if (!info->attrs[NL802154_ATTR_MAX_CSMA_BACKOFFS])
		return -EINVAL;

	max_csma_backoffs = nla_get_u8(
			info->attrs[NL802154_ATTR_MAX_CSMA_BACKOFFS]);
	if (max_csma_backoffs < 0 || max_csma_backoffs > 5)
		return -EINVAL;

	return rdev_set_max_csma_backoffs(rdev, wpan_dev, max_csma_backoffs);
}

static int nl802154_set_min_be(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];
	u8 min_be;

	if (!info->attrs[NL802154_ATTR_MIN_BE])
		return -EINVAL;

	min_be = nla_get_u8(info->attrs[NL802154_ATTR_MIN_BE]);
	if (min_be < 0 || min_be > wpan_dev->max_be)
		return -EINVAL;

	return rdev_set_min_be(rdev, wpan_dev, min_be);
}

#define NL802154_FLAG_NEED_WPAN_PHY	0x01
#define NL802154_FLAG_NEED_NETDEV	0x02
#define NL802154_FLAG_NEED_RTNL		0x04
#define NL802154_FLAG_CHECK_NETDEV_UP	0x08
#define NL802154_FLAG_NEED_NETDEV_UP	(NL802154_FLAG_NEED_NETDEV |\
					 NL802154_FLAG_CHECK_NETDEV_UP)
#define NL802154_FLAG_NEED_WPAN_DEV	0x10
#define NL802154_FLAG_NEED_WPAN_DEV_UP	(NL802154_FLAG_NEED_WPAN_DEV |\
					 NL802154_FLAG_CHECK_NETDEV_UP)

static int nl802154_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
			     struct genl_info *info)
{
	struct cfg802154_registered_device *rdev;
	struct wpan_dev *wpan_dev;
	struct net_device *dev;
	bool rtnl = ops->internal_flags & NL802154_FLAG_NEED_RTNL;

	if (rtnl)
		rtnl_lock();

	if (ops->internal_flags & NL802154_FLAG_NEED_WPAN_PHY) {
		rdev = cfg802154_get_dev_from_info(genl_info_net(info), info);
		if (IS_ERR(rdev)) {
			if (rtnl)
				rtnl_unlock();
			return PTR_ERR(rdev);
		}
		info->user_ptr[0] = rdev;
	} else if (ops->internal_flags & NL802154_FLAG_NEED_NETDEV ||
		   ops->internal_flags & NL802154_FLAG_NEED_WPAN_DEV) {
		ASSERT_RTNL();
		wpan_dev = __cfg802154_wpan_dev_from_attrs(genl_info_net(info),
							   info->attrs);
		if (IS_ERR(wpan_dev)) {
			if (rtnl)
				rtnl_unlock();
			return PTR_ERR(wpan_dev);
		}

		dev = wpan_dev->netdev;
		rdev = wpan_phy_to_rdev(wpan_dev->wpan_phy);

		if (ops->internal_flags & NL802154_FLAG_NEED_NETDEV) {
			if (!dev) {
				if (rtnl)
					rtnl_unlock();
				return -EINVAL;
			}

			info->user_ptr[1] = dev;
		} else {
			info->user_ptr[1] = wpan_dev;
		}

		if (dev) {
			if (ops->internal_flags & NL802154_FLAG_CHECK_NETDEV_UP &&
			    !netif_running(dev)) {
				if (rtnl)
					rtnl_unlock();
				return -ENETDOWN;
			}

			dev_hold(dev);
		}

		info->user_ptr[0] = rdev;
	}

	return 0;
}

static void nl802154_post_doit(const struct genl_ops *ops, struct sk_buff *skb,
			       struct genl_info *info)
{
	if (info->user_ptr[1]) {
		if (ops->internal_flags & NL802154_FLAG_NEED_WPAN_DEV) {
			struct wpan_dev *wpan_dev = info->user_ptr[1];

			if (wpan_dev->netdev)
				dev_put(wpan_dev->netdev);
		} else {
			dev_put(info->user_ptr[1]);
		}
	}

	if (ops->internal_flags & NL802154_FLAG_NEED_RTNL)
		rtnl_unlock();
}

static const struct genl_ops nl802154_ops[] = {
	{
		.cmd = NL802154_CMD_NEW_INTERFACE,
		.doit = nl802154_new_interface,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_DEL_INTERFACE,
		.doit = nl802154_del_interface,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_PAGE,
		.doit = nl802154_set_page,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_CHANNEL,
		.doit = nl802154_set_channel,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_TX_POWER,
		.doit = nl802154_set_tx_power,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_CCA_MODE,
		.doit = nl802154_set_cca_mode,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_PAN_ID,
		.doit = nl802154_set_pan_id,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_MAX_FRAME_RETRIES,
		.doit = nl802154_set_max_frame_retries,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_MAX_BE,
		.doit = nl802154_set_max_be,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_MAX_CSMA_BACKOFFS,
		.doit = nl802154_set_max_csma_backoffs,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_MIN_BE,
		.doit = nl802154_set_min_be,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
};

/* notification functions */

void nl802154_notify_wpan_phy(struct cfg802154_registered_device *rdev,
			      enum nl802154_commands cmd)
{
	struct sk_buff *msg;
	struct nl802154_dump_wpan_phy_state state = {};

	WARN_ON(cmd != NL802154_CMD_NEW_WPAN_PHY &&
		cmd != NL802154_CMD_DEL_WPAN_PHY);

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	if (nl802154_send_wpan_phy(rdev, cmd, msg, 0, 0, 0, &state) < 0) {
		nlmsg_free(msg);
		return;
	}

	genlmsg_multicast_netns(&nl802154_fam, wpan_phy_net(&rdev->wpan_phy),
				msg, 0, NL802154_MCGRP_CONFIG, GFP_KERNEL);
}

static int nl802154_netlink_notify(struct notifier_block * nb,
				   unsigned long state, void *_notify)
{
	struct netlink_notify *notify = _notify;
	struct cfg802154_registered_device *rdev;
	struct wpan_dev *wpan_dev;

	if (state != NETLINK_URELEASE)
		return NOTIFY_DONE;

	rcu_read_lock();

	list_for_each_entry_rcu(rdev, &cfg802154_rdev_list, list) {
		bool schedule_destroy_work = false;

		list_for_each_entry_rcu(wpan_dev, &rdev->wpan_dev_list, list) {
			/* TODO MLME garbage collector here */

			if (wpan_dev->owner_nlportid == notify->portid)
				schedule_destroy_work = true;
		}

		if (schedule_destroy_work) {
			struct cfg802154_iface_destroy *destroy;

			destroy = kzalloc(sizeof(*destroy), GFP_ATOMIC);
			if (destroy) {
				destroy->nlportid = notify->portid;
				spin_lock(&rdev->destroy_list_lock);
				list_add(&destroy->list, &rdev->destroy_list);
				spin_unlock(&rdev->destroy_list_lock);
				schedule_work(&rdev->destroy_work);
			}
		}
	}

	rcu_read_unlock();

	return NOTIFY_OK;
}

static struct notifier_block nl802154_netlink_notifier = {
	.notifier_call = nl802154_netlink_notify,
};

/* initialisation/exit functions */

int nl802154_init(void)
{
	int err;

	err = genl_register_family_with_ops_groups(&nl802154_fam, nl802154_ops,
						   nl802154_mcgrps);
	if (err)
		return err;

	err = netlink_register_notifier(&nl802154_netlink_notifier);
	if (err)
		goto err_out;

	return 0;
err_out:
	genl_unregister_family(&nl802154_fam);
	return err;
}

void nl802154_exit(void)
{
	netlink_unregister_notifier(&nl802154_netlink_notifier);
	genl_unregister_family(&nl802154_fam);
}

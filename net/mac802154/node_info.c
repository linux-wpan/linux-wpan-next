/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Authors:
 * (C) 2016 Pengutronix, Alexander Aring <aar@pengutronix.de>
 *
 * Based on: net/mac80211/sta_info.c
 */

#include <linux/jhash.h>
#include <linux/ieee802154.h>

#include "ieee802154_i.h"
#include "node_info.h"

static int node_info_compare(struct rhashtable_compare_arg *arg, const void *obj);

static const struct rhashtable_params node_rht_params = {
	.nelem_hint = 3, /* start small */
	.automatic_shrinking = true,
	.head_offset = offsetof(struct node_info, hash_node),
	.key_offset = offsetof(struct node_info, extended_addr),
	.key_len = FIELD_SIZEOF(struct node_info, extended_addr),
	.hashfn = node_info_hash,
	.obj_cmpfn = node_info_compare,
};

static int node_info_compare(struct rhashtable_compare_arg *arg, const void *obj)
{
	const struct node_info *info = obj;

	return memcmp(arg->key, &info->extended_addr, node_rht_params.key_len);
}

u32 node_info_hash(const void *key, u32 length, u32 seed)
{
	return jhash(key, node_rht_params.key_len, seed);
}

int node_info_hash_add(struct ieee802154_local *local, struct node_info *node)
{
	return rhashtable_insert_fast(&local->node_hash, &node->hash_node,
				      node_rht_params);
}

struct node_info *node_info_hash_lookup(struct ieee802154_local *local, __le64 *extended_addr)
{
	return rhashtable_lookup_fast(&local->node_hash, extended_addr, node_rht_params);
}

static struct node_info *node_info_alloc(struct ieee802154_local *local, __le64 *extended_addr)
{
	struct node_info *ninfo;

	ninfo = kzalloc(sizeof(*ninfo), GFP_ATOMIC);
	if (!ninfo)
		return ERR_PTR(-ENOMEM);

	ninfo->extended_addr = *extended_addr;
	ninfo->local = local;

	return ninfo;
}

static void node_info_rx_update(struct node_info *ninfo, struct ieee802154_rx_info *rx_info)
{
	memcpy(&ninfo->rx_info, &rx_info, sizeof(rx_info));

	if (unlikely(!ninfo->received))
		ninfo->received = true;
}

int node_info_rx_insert_or_update(struct ieee802154_local *local, __le64 *extended_addr,
				  struct ieee802154_rx_info *rx_info)
{
	struct node_info *ninfo;

	ninfo = node_info_hash_lookup(local, extended_addr);
	if (!ninfo) {
		ninfo = node_info_alloc(local, extended_addr);
		if (IS_ERR(ninfo))
			return PTR_ERR(ninfo);

		node_info_rx_update(ninfo, rx_info);
		node_info_insert(ninfo);
	} else {
		write_lock_bh(&ninfo->lock);
		node_info_rx_update(ninfo, rx_info);
		write_unlock_bh(&ninfo->lock);
	}

	return 0;
}

static void node_info_tx_update(struct node_info *ninfo, enum ieee802154_tx_status status)
{
	switch (status) {
	case IEEE802154_TX_SUCCESS:
		ninfo->tx_stats.success++;
		break;
	case IEEE802154_TX_NO_ACK:
		ninfo->tx_stats.no_ack++;
		break;
	case IEEE802154_TX_CSMA_FAILURE:
		ninfo->tx_stats.csma_failure++;
		break;
	}
}

int node_info_tx_insert_or_update(struct ieee802154_local *local, __le64 *extended_addr,
				  enum ieee802154_tx_status status)
{
	struct node_info *ninfo;

	ninfo = node_info_hash_lookup(local, extended_addr);
	if (!ninfo) {
		ninfo = node_info_alloc(local, extended_addr);
		if (IS_ERR(ninfo))
			return PTR_ERR(ninfo);

		node_info_tx_update(ninfo, status);
		node_info_insert(ninfo);
	} else {
		write_lock_bh(&ninfo->lock);
		node_info_tx_update(ninfo, status);
		write_unlock_bh(&ninfo->lock);
	}

	return 0;
}

int node_info_insert(struct node_info *node)
{
	struct ieee802154_local *local = node->local;
	int err;

	err = node_info_hash_add(local, node);
	if (err)
		return err;

	list_add_tail_rcu(&node->list, &local->node_list);

	return 0;
}

/**
 * sta_info_free - free STA
 *
 * @local: pointer to the global information
 * @sta: STA info to free
 *
 * This function must undo everything done by sta_info_alloc()
 * that may happen before sta_info_insert(). It may only be
 * called when sta_info_insert() has not been attempted (and
 * if that fails, the station is freed anyway.)
 */
void node_info_free(struct ieee802154_local *local, struct node_info *node)
{
#if 0
	if (sta->rate_ctrl)
		rate_control_free_sta(sta);

	sta_dbg(sta->sdata, "Destroyed STA %pM\n", sta->sta.addr);

	if (sta->sta.txq[0])
		kfree(to_txq_info(sta->sta.txq[0]));
	kfree(rcu_dereference_raw(sta->sta.rates));
#ifdef CONFIG_MAC80211_MESH
	kfree(sta->mesh);
#endif
	free_percpu(sta->pcpu_rx_stats);
#endif
	kfree(node);
}

static int node_info_insert_check(struct node_info *node)
{
#if 0
	struct ieee80211_sub_if_data *sdata = sta->sdata;

	/*
	 * Can't be a WARN_ON because it can be triggered through a race:
	 * something inserts a STA (on one CPU) without holding the RTNL
	 * and another CPU turns off the net device.
	 */
	if (unlikely(!ieee80211_sdata_running(sdata)))
		return -ENETDOWN;

	if (WARN_ON(ether_addr_equal(sta->sta.addr, sdata->vif.addr) ||
		    is_multicast_ether_addr(sta->sta.addr)))
		return -EINVAL;

	/* Strictly speaking this isn't necessary as we hold the mutex, but
	 * the rhashtable code can't really deal with that distinction. We
	 * do require the mutex for correctness though.
	 */
	rcu_read_lock();
	lockdep_assert_held(&sdata->local->sta_mtx);
	if (ieee80211_hw_check(&sdata->local->hw, NEEDS_UNIQUE_STA_ADDR) &&
	    ieee80211_find_sta_by_ifaddr(&sdata->local->hw, sta->addr, NULL)) {
		rcu_read_unlock();
		return -ENOTUNIQ;
	}
	rcu_read_unlock();
#endif

	return 0;
}

/*
 * should be called with node_mtx locked
 * this function replaces the mutex lock
 * with a RCU lock
 */
static int node_info_insert_finish(struct node_info *node) __acquires(RCU)
{
	struct ieee802154_local *local = node->local;
//	struct ieee802154_sub_if_data *sdata = node->sdata;
	struct ieee802154_node_info *ninfo;
	int err = 0;

//	lockdep_assert_held(&local->node_mtx);

#if 0
	ninfo = kzalloc(sizeof(*ninfo), GFP_KERNEL);
	if (!ninfo) {
		err = -ENOMEM;
		goto out_err;
	}

	/* check if STA exists already */
	if (sta_info_get_bss(sdata, sta->sta.addr)) {
		err = -EEXIST;
		goto out_err;
	}

	local->num_sta++;
	local->sta_generation++;
	smp_mb();
#endif

	/* make the station visible */
	err = node_info_hash_add(local, node);
	if (err)
		return err;

	list_add_tail_rcu(&node->list, &local->node_list);

	//sinfo->generation = local->sta_generation;
	//cfg80211_new_sta(sdata->dev, sta->sta.addr, sinfo, GFP_KERNEL);
//	kfree(ninfo);

	//sta_dbg(sdata, "Inserted STA %pM\n", sta->sta.addr);

	/* move reference to rcu-protected */
//	rcu_read_lock();
//	mutex_unlock(&local->node_mtx);

	return 0;
#if 0
 out_remove:
	sta_info_hash_del(local, sta);
	list_del_rcu(&sta->list);
 out_drop_sta:
	local->num_sta--;
	synchronize_net();
	__cleanup_single_sta(sta);
 out_err:
	mutex_unlock(&local->node_mtx);
	kfree(ninfo);
	rcu_read_lock();
	return err;
#endif
}

int node_info_insert_rcu(struct node_info *node) __acquires(RCU)
{
	struct ieee802154_local *local = node->local;
	int err;

	might_sleep();

//	mutex_lock(&local->node_mtx);

	err = node_info_insert_check(node);
	if (err) {
//		mutex_unlock(&local->node_mtx);
		rcu_read_lock();
		goto out_free;
	}

	err = node_info_insert_finish(node);
	if (err)
		goto out_free;

	return 0;
 out_free:
	node_info_free(local, node);
	return err;
}

int node_info_init(struct ieee802154_local *local)
{
	int err;

	err = rhashtable_init(&local->node_hash, &node_rht_params);
	if (err < 0)
		return err;

	rwlock_init(&local->node_lock);
	INIT_LIST_HEAD(&local->node_list);
	return 0;
}

void node_info_stop(struct ieee802154_local *local)
{
	rhashtable_destroy(&local->node_hash);
}

struct node_info *node_info_get_by_idx(struct ieee802154_sub_if_data *sdata,
				       int idx)
{
	struct ieee802154_local *local = sdata->local;
	struct node_info *node;
	int i = 0;

	list_for_each_entry_rcu(node, &local->node_list, list) {
		if (i < idx) {
			++i;
			continue;
		}
		return node;
	}

	return NULL;
}

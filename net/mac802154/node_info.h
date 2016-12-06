#ifndef NODE_INFO_H
#define NODE_INFO_H

#include <linux/rhashtable.h>

#include "ieee802154_i.h"

struct node_info {
	struct rhash_head hash_node;
	__le64 extended_addr;
	rwlock_t lock;

	struct ieee802154_sub_if_data *sdata;
	struct ieee802154_local *local;

	struct list_head list;

	struct ieee802154_rx_info rx_info;
	u64 lqi_sum;
	u64 received;
	struct {
		u64 success;
		u64 no_ack;
		u64 csma_failure;
	} tx_stats;
};

int node_info_init(struct ieee802154_local *local);
void node_info_stop(struct ieee802154_local *local);

int node_info_hash_add(struct ieee802154_local *local, struct node_info *node);
struct node_info *node_info_hash_lookup(struct ieee802154_local *local, __le64 *extended_addr);
u32 node_info_hash(const void *key, u32 length, u32 seed);
int node_info_insert(struct node_info *node);

int node_info_tx_broadcast(struct ieee802154_local *local, enum ieee802154_tx_status status);
int node_info_tx_insert_or_update(struct ieee802154_local *local, __le64 *extended_addr,
				  enum ieee802154_tx_status status, bool was_ack_request);
int node_info_rx_insert_or_update(struct ieee802154_local *local, __le64 *extended_addr,
				  struct ieee802154_rx_info *rx_info);
struct node_info *node_info_get_by_idx(struct ieee802154_sub_if_data *sdata,
				       int idx);
#endif /* NODE_INFO_H */

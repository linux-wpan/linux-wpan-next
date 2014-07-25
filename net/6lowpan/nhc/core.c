/*	6LoWPAN next header compression
 *
 *
 *	Authors:
 *	Alexander Aring		<aar@pengutronix.de>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/netdevice.h>

#include <net/ipv6.h>

#include "core.h"
#include "udp.h"
#include "hop.h"
#include "route.h"
#include "frag.h"
#include "dest.h"
#include "mobil.h"
#include "ipv6.h"

static struct rb_root rb_root = RB_ROOT;
static struct lowpan_nhc *lowpan_nexthdr_nhcs[NEXTHDR_MAX];

static int lowpan_insert_nhc(struct lowpan_nhc *nhc)
{
	struct rb_node **new = &rb_root.rb_node, *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct lowpan_nhc *this = container_of(*new, struct lowpan_nhc,
						       node);
		int result, len_dif, len;

		len_dif = nhc->idlen - this->idlen;

		if (nhc->idlen < this->idlen)
			len = nhc->idlen;
		else
			len = this->idlen;

		result = memcmp(nhc->id, this->id, len);
		if (!result)
			result = len_dif;

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return -EEXIST;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&nhc->node, parent, new);
	rb_insert_color(&nhc->node, &rb_root);

	return 0;
}

static void lowpan_remove_nhc(struct lowpan_nhc *nhc)
{
	rb_erase(&nhc->node, &rb_root);
}

struct lowpan_nhc *lowpan_search_nhc_by_nhcid(const struct sk_buff *skb)
{
	struct rb_node *node = rb_root.rb_node;
	const u8 *nhcid_skb_ptr = skb->data;

	while (node) {
		struct lowpan_nhc *nhc = container_of(node, struct lowpan_nhc,
						      node);
		u8 nhcid_skb_ptr_masked[nhc->idlen];
		int result, i;

		if (nhcid_skb_ptr + nhc->idlen > skb->data + skb->len)
			return NULL;

		/* copy and mask afterwards the nhid value from skb */
		memcpy(nhcid_skb_ptr_masked, nhcid_skb_ptr, nhc->idlen);
		for (i = 0; i < nhc->idlen; i++)
			nhcid_skb_ptr_masked[i] &= nhc->idmask[i];

		result = memcmp(nhcid_skb_ptr_masked, nhc->id, nhc->idlen);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return nhc;
	}

	return NULL;
}
EXPORT_SYMBOL(lowpan_search_nhc_by_nhcid);

struct lowpan_nhc *lowpan_search_nhc_by_nexthdr(const u8 nexthdr)
{
	return lowpan_nexthdr_nhcs[nexthdr];
}
EXPORT_SYMBOL(lowpan_search_nhc_by_nexthdr);

int lowpan_nhc_do_compression(struct lowpan_nhc *nhc, struct sk_buff *skb,
			      u8 **hc_ptr, u8 *iphc0)
{
	int ret = 0;

	if (!nhc)
		return 0;

	ret = nhc->compress(skb, hc_ptr);
	if (!ret)
		*iphc0 |= LOWPAN_IPHC_NH_C;
	else if (ret == -ENOTSUPP)
		return 0;

	return ret;
}
EXPORT_SYMBOL(lowpan_nhc_do_compression);

int lowpan_nhc_do_uncompression(struct sk_buff **skb, struct ipv6hdr *hdr)
{
	struct lowpan_nhc *nhc;
	int ret = 0;

	nhc = lowpan_search_nhc_by_nhcid(*skb);
	if (nhc) {
		ret = nhc->uncompress(skb);
		if (!ret) {
			skb_reset_transport_header(*skb);
			hdr->nexthdr = nhc->nexthdr;
		} else if (ret == -ENOTSUPP) {
			net_warn_ratelimited("%s received %s which is not supported.\n",
					     (*skb)->dev->name, nhc->name);
		}
	}

	return ret;
}
EXPORT_SYMBOL(lowpan_nhc_do_uncompression);

int lowpan_add_nhc(struct lowpan_nhc *nhc)
{
	int ret = -ENOMEM;

	if (!nhc->uncompress || !nhc->idlen || !nhc->idsetup || !nhc->compress)
		return -EINVAL;

	nhc->idsetup(nhc);

	if (lowpan_nexthdr_nhcs[nhc->nexthdr])
		return -EEXIST;

	ret = lowpan_insert_nhc(nhc);
	if (ret < 0)
		goto out;

	lowpan_nexthdr_nhcs[nhc->nexthdr] = nhc;
out:
	return ret;
}
EXPORT_SYMBOL(lowpan_add_nhc);

void lowpan_del_nhc(struct lowpan_nhc *nhc)
{
	lowpan_remove_nhc(nhc);
	lowpan_nexthdr_nhcs[nhc->nexthdr] = NULL;

	synchronize_net();
}
EXPORT_SYMBOL(lowpan_del_nhc);

int lowpan_init_nhc(void)
{
	int ret;

	ret = lowpan_init_nhc_udp();
	if (ret < 0)
		goto out;

	ret = lowpan_init_nhc_hop();
	if (ret < 0)
		goto hop_fail;

	ret = lowpan_init_nhc_route();
	if (ret < 0)
		goto route_fail;

	ret = lowpan_init_nhc_frag();
	if (ret < 0)
		goto frag_fail;

	ret = lowpan_init_nhc_dest();
	if (ret < 0)
		goto dest_fail;

	ret = lowpan_init_nhc_mobil();
	if (ret < 0)
		goto mobil_fail;

	ret = lowpan_init_nhc_ipv6();
	if (ret < 0)
		goto ipv6_fail;
out:
	return ret;

ipv6_fail:
	lowpan_cleanup_nhc_mobil();
mobil_fail:
	lowpan_cleanup_nhc_dest();
dest_fail:
	lowpan_cleanup_nhc_frag();
frag_fail:
	lowpan_cleanup_nhc_route();
route_fail:
	lowpan_cleanup_nhc_hop();
hop_fail:
	lowpan_cleanup_nhc_udp();
	goto out;
}

void lowpan_cleanup_nhc(void)
{
	lowpan_cleanup_nhc_udp();
	lowpan_cleanup_nhc_hop();
	lowpan_cleanup_nhc_route();
	lowpan_cleanup_nhc_frag();
	lowpan_cleanup_nhc_dest();
	lowpan_cleanup_nhc_mobil();
	lowpan_cleanup_nhc_ipv6();
}

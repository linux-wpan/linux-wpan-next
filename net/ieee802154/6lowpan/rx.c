/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/if_arp.h>

#include <net/6lowpan.h>
#include <net/ieee802154_netdev.h>

#include "6lowpan_i.h"

typedef unsigned __bitwise__ lowpan_rx_result;
#define RX_CONTINUE		((__force lowpan_rx_result) 0u)
#define RX_DROP_UNUSABLE	((__force lowpan_rx_result) 1u)
#define RX_DROP			((__force lowpan_rx_result) 2u)
#define RX_QUEUED		((__force lowpan_rx_result) 3u)

#define LOWPAN_DISPATCH_FIRST		0xc0
#define LOWPAN_DISPATCH_FRAG_MASK	0xf8
#define LOWPAN_DISPATCH_IPHC_MASK	0xe0

#define LOWPAN_DISPATCH_NALP		0x00
#define LOWPAN_DISPATCH_HC1		0x42
#define LOWPAN_DISPATCH_BC0		0x50
#define LOWPAN_DISPATCH_ESC		0x7f
#define LOWPAN_DISPATCH_MESH		0x80

static int
lowpan_rx_handlers_result(struct sk_buff *skb, lowpan_rx_result res)
{
	switch (res) {
	/* nobody cared about this packet */
	case RX_CONTINUE:
		net_warn_ratelimited("%s: %s 0x%02x\n", skb->dev->name,
				     "received unknown dispatch",
				     *skb_network_header(skb));
	case RX_DROP_UNUSABLE:
		kfree_skb(skb);
	case RX_DROP:
		return NET_RX_DROP;
	default:
		break;
	}

	return NET_RX_SUCCESS;
}

static int lowpan_give_skb_to_device(struct sk_buff *skb)
{
	int ret;

	skb->protocol = htons(ETH_P_IPV6);

	ret = netif_rx(skb);
	/* kfree_skb handled by netif_rx, so RX_DROP on failure */
	if (ret == NET_RX_SUCCESS)
		return RX_QUEUED;
	else
		return RX_DROP;
}

static int
iphc_decompress(struct sk_buff *skb, const struct ieee802154_hdr *hdr)
{
	u8 iphc0, iphc1;
	struct ieee802154_addr_sa sa, da;
	void *sap, *dap;

	raw_dump_table(__func__, "raw skb data dump", skb->data, skb->len);

	if (lowpan_fetch_skb_u8(skb, &iphc0) ||
	    lowpan_fetch_skb_u8(skb, &iphc1))
		return -EINVAL;

	ieee802154_addr_to_sa(&sa, &hdr->source);
	ieee802154_addr_to_sa(&da, &hdr->dest);

	if (sa.addr_type == IEEE802154_ADDR_SHORT)
		sap = &sa.short_addr;
	else
		sap = &sa.hwaddr;

	if (da.addr_type == IEEE802154_ADDR_SHORT)
		dap = &da.short_addr;
	else
		dap = &da.hwaddr;

	return lowpan_header_decompress(skb, skb->dev, sap, sa.addr_type,
					IEEE802154_ADDR_LEN, dap, da.addr_type,
					IEEE802154_ADDR_LEN, iphc0, iphc1);
}

static lowpan_rx_result lowpan_rx_h_ipv6(struct sk_buff *skb)
{
	if (!lowpan_is_ipv6(*skb_network_header(skb)))
		return RX_CONTINUE;

	/* Pull off the 1-byte of 6lowpan header. */
	skb_pull(skb, 1);
	return lowpan_give_skb_to_device(skb);
}

static inline bool lowpan_is_frag1(u8 dispatch)
{
	return (dispatch & LOWPAN_DISPATCH_FRAG_MASK) == LOWPAN_DISPATCH_FRAG1;
}

static inline bool lowpan_is_fragn(u8 dispatch)
{
	return (dispatch & LOWPAN_DISPATCH_FRAG_MASK) == LOWPAN_DISPATCH_FRAGN;
}

static lowpan_rx_result lowpan_rx_h_frag(struct sk_buff *skb)
{
	int ret;

	if (!(lowpan_is_frag1(*skb_network_header(skb)) ||
	      lowpan_is_fragn(*skb_network_header(skb))))
		return RX_CONTINUE;

	ret = lowpan_frag_rcv(skb, *skb_network_header(skb) &
			      LOWPAN_DISPATCH_FRAG_MASK);
	if (ret == 1)
		return RX_CONTINUE;

	/* packet is dropped and putted into the frag bucket only */
	return RX_DROP;
}

static lowpan_rx_result lowpan_rx_h_iphc(struct sk_buff *skb)
{
	int ret;
	struct ieee802154_hdr hdr;

	if (!lowpan_is_iphc(*skb_network_header(skb)))
		return RX_CONTINUE;

	if (ieee802154_hdr_peek_addrs(skb, &hdr) < 0)
		return RX_DROP_UNUSABLE;

	ret = iphc_decompress(skb, &hdr);
	if (ret < 0)
		return RX_DROP_UNUSABLE;

	return lowpan_give_skb_to_device(skb);
}

static inline bool lowpan_is_hc1(u8 dispatch)
{
	return dispatch == LOWPAN_DISPATCH_HC1;
}

static lowpan_rx_result lowpan_rx_h_hc1(struct sk_buff *skb)
{
	if (!lowpan_is_hc1(*skb_network_header(skb)))
		return RX_CONTINUE;

	net_warn_ratelimited("%s: %s\n", skb->dev->name,
			     "6LoWPAN HC1 not supported\n");

	return RX_DROP_UNUSABLE;
}

static inline bool lowpan_is_bc0(u8 dispatch)
{
	return dispatch == LOWPAN_DISPATCH_BC0;
}

static lowpan_rx_result lowpan_rx_h_bc0(struct sk_buff *skb)
{
	if (!lowpan_is_bc0(*skb_network_header(skb)))
		return RX_CONTINUE;

	net_warn_ratelimited("%s: %s\n", skb->dev->name,
			     "6LoWPAN BC0 not supported\n");

	return RX_DROP_UNUSABLE;
}

static inline bool lowpan_is_esc(u8 dispatch)
{
	return dispatch == LOWPAN_DISPATCH_ESC;
}

static lowpan_rx_result lowpan_rx_h_esc(struct sk_buff *skb)
{
	if (!lowpan_is_esc(*skb_network_header(skb)))
		return RX_CONTINUE;

	net_warn_ratelimited("%s: %s\n", skb->dev->name,
			     "6LoWPAN ESC not supported\n");

	return RX_DROP_UNUSABLE;
}

static inline bool lowpan_is_mesh(u8 dispatch)
{
	return (dispatch & LOWPAN_DISPATCH_FIRST) == LOWPAN_DISPATCH_MESH;
}

static lowpan_rx_result lowpan_rx_h_mesh(struct sk_buff *skb)
{
	if (!lowpan_is_mesh(*skb_network_header(skb)))
		return RX_CONTINUE;

	net_warn_ratelimited("%s: %s\n", skb->dev->name,
			     "6LoWPAN MESH not supported\n");

	return RX_DROP_UNUSABLE;
}

int lowpan_invoke_rx_handlers(struct sk_buff *skb)
{
	lowpan_rx_result res;

#define CALL_RXH(rxh)			\
	do {				\
		res = rxh(skb);		\
		if (res != RX_CONTINUE)	\
			goto rxh_next;	\
	} while (0)

	/* frag at first, because it contains dispatch value again */
	CALL_RXH(lowpan_rx_h_frag);

	/* likely at first */
	CALL_RXH(lowpan_rx_h_iphc);
	CALL_RXH(lowpan_rx_h_ipv6);
	CALL_RXH(lowpan_rx_h_hc1);
	CALL_RXH(lowpan_rx_h_bc0);
	CALL_RXH(lowpan_rx_h_esc);
	CALL_RXH(lowpan_rx_h_mesh);

rxh_next:
	return lowpan_rx_handlers_result(skb, res);
#undef CALL_RXH
}

static inline bool lowpan_is_nalp(u8 dispatch)
{
	return (dispatch & LOWPAN_DISPATCH_FIRST) == LOWPAN_DISPATCH_NALP;
}

static inline bool lowpan_is_reserved(u8 dispatch)
{
	return !(lowpan_is_nalp(dispatch) || lowpan_is_iphc(dispatch) ||
		 lowpan_is_ipv6(dispatch) || lowpan_is_hc1(dispatch) ||
		 lowpan_is_bc0(dispatch) || lowpan_is_mesh(dispatch) ||
		 lowpan_is_esc(dispatch) || lowpan_is_frag1(dispatch) ||
		 lowpan_is_fragn(dispatch));
}

/* lowpan_rx_h_check checks on generic 6LoWPAN requirements
 * in MAC and 6LoWPAN header.
 *
 * Don't manipulate the skb here, it could be shared buffer.
 */
static bool lowpan_rx_h_check(struct sk_buff *skb)
{
	__le16 fc = ieee802154_get_fc_from_skb(skb);

	/* check on ieee802154 conform 6LoWPAN header */
	if (!ieee802154_is_data(fc) ||
	    ieee802154_is_daddr_none(fc) ||
	    ieee802154_is_saddr_none(fc) ||
	    !ieee802154_is_intra_pan(fc))
		return false;

	/* check for if we can evaluate the dispatch */
	if (unlikely(!skb->len))
		return false;

	if (lowpan_is_nalp(*skb_network_header(skb)) ||
	    lowpan_is_reserved(*skb_network_header(skb)))
		return false;

	return true;
}

static int lowpan_rcv(struct sk_buff *skb, struct net_device *wdev,
		      struct packet_type *pt, struct net_device *orig_wdev)
{
	if (skb->pkt_type == PACKET_OTHERHOST ||
	    wdev->type != ARPHRD_IEEE802154 ||
	    !lowpan_rx_h_check(skb))
		return NET_RX_DROP;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return NET_RX_DROP;

	skb->dev = wdev->ieee802154_ptr->lowpan_dev;
	return lowpan_invoke_rx_handlers(skb);
}

static struct packet_type lowpan_packet_type = {
	.type = htons(ETH_P_IEEE802154),
	.func = lowpan_rcv,
};

void lowpan_rx_init(void)
{
	dev_add_pack(&lowpan_packet_type);
}

void lowpan_rx_exit(void)
{
	dev_remove_pack(&lowpan_packet_type);
}

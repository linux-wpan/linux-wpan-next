#ifndef __6LOWPAN_NHC_H
#define __6LOWPAN_NHC_H

#include <linux/skbuff.h>
#include <linux/rbtree.h>
#include <linux/list.h>

#include <net/6lowpan.h>
#include <net/ipv6.h>

/**
 * LOWPAN_NHC - helper macro to generate nh id fields and lowpan_nhc struct
 *
 * @varname: variable name of the lowpan_nhc struct.
 * @nhcname: const char * of common header compression name.
 * @nexthdr: ipv6 nexthdr field for the header compression.
 * @nhidsetup: callback to setup id and mask values.
 * @nhidlen: len for the next header id and mask, should be always the same.
 * @nhuncompress: callback for uncompression call.
 * @nhcompress: callback for compression call.
 */
#define LOWPAN_NHC(varname, nhcname, nhnexthdr,	\
		   nhidsetup, nhidlen,		\
		   nhuncompress, nhcompress)	\
	static u8 name##_val[nhidlen];		\
	static u8 name##_mask[nhidlen];		\
	static struct lowpan_nhc varname = {	\
		.name		= nhcname,	\
		.nexthdr	= nhnexthdr,	\
		.id		= name##_val,	\
		.idmask		= name##_mask,	\
		.idlen		= nhidlen,	\
		.idsetup	= nhidsetup,	\
		.uncompress	= nhuncompress,	\
		.compress	= nhcompress,	\
	}

/**
 * struct lowpan_nhc - hold 6lowpan next hdr compression ifnformation
 *
 * @node: holder for the rbtree.
 * @name: name of the specific next header compression
 * @nexthdr: next header value of the protocol which should be compressed.
 * @id: array for nhc id. Note this need to be in network byteorder.
 * @mask: array for nhc id mask. Note this need to be in network byteorder.
 * @len: the length of the next header id and mask.
 * @setup: callback to setup fill the next header id value and mask.
 * @compress: callback to do the header compression.
 * @uncompress: callback to do the header uncompression.
 */
struct lowpan_nhc {
	struct rb_node	node;
	const char	*name;
	const u8	nexthdr;
	u8		*id;
	u8		*idmask;
	const size_t	idlen;

	void		(*idsetup)(struct lowpan_nhc *nhc);
	int		(*uncompress)(struct sk_buff **skb);
	int		(*compress)(struct sk_buff *skb, u8 **hc_ptr);
};

/**
 * lowpan_search_nhc_by_nhcid - returns the 6lowpan nhc by nhcid
 *
 * @skb: skb with skb->data which is pointed to 6lowpan nhc id.
 */
struct lowpan_nhc *lowpan_search_nhc_by_nhcid(const struct sk_buff *skb);

/**
 * lowpan_search_nhc_by_nexthdr - return the 6lowpan nhc by ipv6 nexthdr.
 *
 * @nexthdr: ipv6 nexthdr value.
 */
struct lowpan_nhc *lowpan_search_nhc_by_nexthdr(const u8 nexthdr);

/**
 * lowpan_add_nhc - register a next header compression to framework
 *
 * @nhc: nhc which should be add.
 */
int lowpan_add_nhc(struct lowpan_nhc *nhc);

/**
 * lowpan_del_nhc - delete a next header compression from framework
 *
 * @nhc: nhc which should be delete.
 */
void lowpan_del_nhc(struct lowpan_nhc *nhc);

/**
 * lowpan_nhc_do_compression - wrapper for calling compress callback
 *
 * @nhc: 6LoWPAN nhc context, get by lowpan_search_nhc_*.
 * @skb: skb of 6LoWPAN header to read nhc and replace header.
 * @hc_ptr: pointer for 6LoWPAN header which should increment at the end of
 *	    replaced header.
 * @iphc0: First iphc byte, to set NHC bit.
 */
int lowpan_nhc_do_compression(struct lowpan_nhc *nhc, struct sk_buff *skb,
			      u8 **hc_ptr, u8 *iphc0);

/**
 * lowpan_nhc_do_uncompression - wrapper for calling uncompress callback
 *
 * @skb: skb of 6LoWPAN header, skb->data should be pointed to nhc id value.
 * @hdr: ipv6 header to set the according nexthdr value.
 */
int lowpan_nhc_do_uncompression(struct sk_buff **skb, struct ipv6hdr *hdr);

/**
 * lowpan_init_nhc - init all nhcs
 */
int lowpan_init_nhc(void);

/**
 * lowpan_cleanup_nhc - cleanup all registered nhcs
 */
void lowpan_cleanup_nhc(void);

#endif /* __6LOWPAN_NHC_H */

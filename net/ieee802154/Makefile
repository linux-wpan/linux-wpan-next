obj-$(CONFIG_IEEE802154) += ieee802154.o af_802154.o
obj-$(CONFIG_IEEE802154_6LOWPAN) += 6lowpan/

ieee802154-y := core.o sysfs.o nl802154.o header_ops.o
af_802154-y := af_ieee802154.o raw.o dgram.o

ccflags-y += -D__CHECK_ENDIAN__

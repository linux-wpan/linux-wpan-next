obj-$(CONFIG_IEEE802154) += ieee802154.o
obj-$(CONFIG_IEEE802154) += af_802154/
obj-$(CONFIG_IEEE802154_6LOWPAN) += 6lowpan/

ieee802154-y := core.o sysfs.o nl802154.o header_ops.o

ccflags-y += -D__CHECK_ENDIAN__

USER_TARGETS += clean-dns
BPF_TARGETS += clean-dns.kern
BPF_SKEL_OBJ += clean-dns.kern.o

LIB_DIR = lib

include $(LIB_DIR)/common.mk


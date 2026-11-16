# Standalone build (host selftest or OpenWrt SDK cross build).
#   make                                  # native gcc
#   make selftest                         # run built-in protocol/feature tests
#   make CROSS=aarch64-openwrt-linux-musl-   # cross compile for the router
# make's built-in CC=cc would break "CROSS + CC" (musl-cc does not exist).
# A command-line CC=... still overrides this for the OpenWrt package build.
CC       = gcc
CROSS   ?=
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu99 -D_GNU_SOURCE
LDFLAGS ?=
SRCS     = oaf_lite.c feature.c probe.c acct.c util.c
OBJS     = $(SRCS:.c=.o)
TARGET   = oaf-lite

.PHONY: all clean selftest

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CROSS)$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm

%.o: %.c common.h
	$(CROSS)$(CC) $(CFLAGS) -c -o $@ $<

selftest: $(TARGET)
	./$(TARGET) --selftest -f ../files/etc/fwxd/feature.cfg

clean:
	rm -f $(OBJS) $(TARGET)

# Copyright (C) 2021, Alliander (http://www.alliander.com)
# SPDX-License-Identifier: Apache-2.0

# binary name
APP = kern-pkt-mirror

# all source are stored in SRCS-y
SRCS-y := kern-pkt-mirror.c

# Build using pkg-config variables if possible

all: shared
.PHONY: shared
shared: build/$(APP)


CFLAGS += -O3 
LDFLAGS +=  

build/$(APP): $(SRCS-y) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS)


build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)
	test -d build && rmdir -p build || true

# PREFIX is environment variable, but if it is not set, then set default value
ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

install:
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 755 build/$(APP) $(DESTDIR)$(PREFIX)/bin/


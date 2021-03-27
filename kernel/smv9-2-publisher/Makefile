# Copyright (C) 2021, Alliander (http://www.alliander.com)
# SPDX-License-Identifier: Apache-2.0

# binary name
APP = kern-smv9-2-publisher

# all source are stored in SRCS-y
SRCS-y := kern-smv9-2-publisher.c

# Build using pkg-config variables if possible

all: shared
.PHONY: shared 
shared: build/$(APP)


CFLAGS += #-O3 
LDFLAGS +=  

build/$(APP): $(SRCS-y) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS)


build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)
	test -d build && rmdir -p build || true

install:
	install -d $(DESTDIR)$(PREFIX)/bin/
	install -m 755 build/$(APP) $(DESTDIR)$(PREFIX)/bin/


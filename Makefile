CC ?= cc
CFLAGS ?= -O3
CFLAGS += -std=c2x -Wall -Wextra -Wpedantic -Wshadow -Wpointer-arith \
	-fwrapv -march=native -mtune=native -Iinclude -Ithird_party/labrador
LDLIBS += -lm

LABRADOR_DIR := third_party/labrador
LABRADOR_SOURCES := \
	$(LABRADOR_DIR)/pack.c $(LABRADOR_DIR)/greyhound.c \
	$(LABRADOR_DIR)/dachshund.c build/labrador/chihuahua.c \
	$(LABRADOR_DIR)/labrador.c $(LABRADOR_DIR)/data.c \
	$(LABRADOR_DIR)/jlproj.c $(LABRADOR_DIR)/polx.c \
	$(LABRADOR_DIR)/poly.c build/labrador/polz.c \
	$(LABRADOR_DIR)/sparsemat.c $(LABRADOR_DIR)/ntt.S \
	$(LABRADOR_DIR)/invntt.S $(LABRADOR_DIR)/aesctr.c \
	$(LABRADOR_DIR)/fips202.c $(LABRADOR_DIR)/randombytes.c \
	$(LABRADOR_DIR)/cpucycles.c

.PHONY: all test prove clean
all: build/test_vc build/test_tree build/prove_opening
build:
	mkdir -p $@
build/labrador:
	mkdir -p $@
build/labrador/chihuahua.c: $(LABRADOR_DIR)/chihuahua.c \
		patches/labrador-mixed-constraints.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-mixed-constraints.patch
build/labrador/polz.c: $(LABRADOR_DIR)/polz.c \
		patches/labrador-zero-length-vla.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-zero-length-vla.patch
build/test_vc: tests/test_vc.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
build/test_tree: tests/test_tree.c src/tree.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
build/prove_opening: examples/prove_opening.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
test: build/test_vc build/test_tree
	./build/test_vc
	./build/test_tree
prove: build/prove_opening
	./build/prove_opening
clean:
	rm -f build/test_vc build/test_tree build/prove_opening

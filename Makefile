CC ?= cc
CFLAGS ?= -O3
CFLAGS += -std=c2x -Wall -Wextra -Wpedantic -Wshadow -Wpointer-arith \
	-D_GNU_SOURCE -fwrapv -march=native -mtune=native \
	-Iinclude -Ithird_party/labrador \
	-include build/labrador/data.h
LDLIBS += -lm

LABRADOR_DIR := third_party/labrador
LABRADOR_SOURCES := \
	$(LABRADOR_DIR)/pack.c $(LABRADOR_DIR)/greyhound.c \
	$(LABRADOR_DIR)/dachshund.c build/labrador/chihuahua.c \
	build/labrador/labrador.c $(LABRADOR_DIR)/data.c \
	$(LABRADOR_DIR)/jlproj.c $(LABRADOR_DIR)/polx.c \
	build/labrador/poly.c build/labrador/polz.c \
	$(LABRADOR_DIR)/sparsemat.c $(LABRADOR_DIR)/ntt.S \
	$(LABRADOR_DIR)/invntt.S $(LABRADOR_DIR)/aesctr.c \
	$(LABRADOR_DIR)/fips202.c build/labrador/randombytes.c \
	$(LABRADOR_DIR)/cpucycles.c

.PHONY: all test test-accumulator test-profiles prove benchmark-profiles \
	analyze-niaok \
	print-build-config clean
all: build/test_vc build/test_tree build/test_accumulator build/prove_opening
build:
	mkdir -p $@
build/labrador:
	mkdir -p $@
build/labrador/data-source.h: $(LABRADOR_DIR)/data.h | build/labrador
	sed 's/\r$$//' $< > $@
build/labrador/data.h: build/labrador/data-source.h \
		patches/labrador-aab24-params.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-aab24-params.patch
build/labrador/labrador-source.c: $(LABRADOR_DIR)/labrador.c | build/labrador
	sed 's/\r$$//' $< > $@
build/labrador/labrador.c: build/labrador/labrador-source.c \
		patches/labrador-aab24-security.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-aab24-security.patch
build/labrador/poly-source.c: $(LABRADOR_DIR)/poly.c | build/labrador
	sed 's/\r$$//' $< > $@
build/labrador/poly.c: build/labrador/poly-source.c \
		patches/labrador-aab24-challenge.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-aab24-challenge.patch
build/labrador/randombytes-source.c: $(LABRADOR_DIR)/randombytes.c | build/labrador
	sed 's/\r$$//' $< > $@
build/labrador/randombytes.c: build/labrador/randombytes-source.c \
		patches/labrador-feature-macro.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-feature-macro.patch
build/labrador/chihuahua-source.c: $(LABRADOR_DIR)/chihuahua.c \
		build/labrador/data.h | build/labrador
	sed 's/\r$$//' $< > $@
build/labrador/chihuahua.c: build/labrador/chihuahua-source.c \
		patches/labrador-mixed-constraints.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-mixed-constraints.patch
build/labrador/polz-source.c: $(LABRADOR_DIR)/polz.c | build/labrador
	sed 's/\r$$//' $< > $@
build/labrador/polz.c: build/labrador/polz-source.c \
		patches/labrador-zero-length-vla.patch | build/labrador
	patch -s -o $@ $< < patches/labrador-zero-length-vla.patch
build/test_vc: tests/test_vc.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
build/test_tree: tests/test_tree.c src/tree.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
build/test_accumulator: tests/test_accumulator.c src/accumulator.c src/wire.c src/tree.c \
		src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
build/prove_opening: examples/prove_opening.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
build/test_vc_p1: tests/test_vc.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P1 $^ -o $@ $(LDLIBS)
build/test_vc_p2: tests/test_vc.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P2 $^ -o $@ $(LDLIBS)
build/test_vc_p3: tests/test_vc.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P3 $^ -o $@ $(LDLIBS)
build/benchmark_p1: bench/benchmark_profiles.c src/accumulator.c src/wire.c \
		src/tree.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P1 $^ -o $@ $(LDLIBS)
build/benchmark_p2: bench/benchmark_profiles.c src/accumulator.c src/wire.c \
		src/tree.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P2 $^ -o $@ $(LDLIBS)
build/benchmark_p3: bench/benchmark_profiles.c src/accumulator.c src/wire.c \
		src/tree.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P3 $^ -o $@ $(LDLIBS)
build/niaok_trace_p1: bench/niaok_trace.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P1 $^ -o $@ $(LDLIBS)
build/niaok_trace_p2: bench/niaok_trace.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P2 $^ -o $@ $(LDLIBS)
build/niaok_trace_p3: bench/niaok_trace.c src/vc.c $(LABRADOR_SOURCES) | build
	$(CC) $(CFLAGS) -DVA_PROFILE_P3 $^ -o $@ $(LDLIBS)
test: build/test_vc build/test_tree
	./build/test_vc
	./build/test_tree
test-accumulator: build/test_accumulator
	./build/test_accumulator
test-profiles: build/test_vc_p1 build/test_vc_p2 build/test_vc_p3
	./build/test_vc_p1
	./build/test_vc_p2
	./build/test_vc_p3
prove: build/prove_opening
	./build/prove_opening
benchmark-profiles: build/benchmark_p1 build/benchmark_p2 build/benchmark_p3
	./build/benchmark_p1
	./build/benchmark_p2 --no-header
	./build/benchmark_p3 --no-header
analyze-niaok: build/niaok_trace_p1 build/niaok_trace_p2 build/niaok_trace_p3
	python3 scripts/analyze_niaok.py \
		--binary build/niaok_trace_p1 \
		--binary build/niaok_trace_p2 \
		--binary build/niaok_trace_p3 \
		--output-dir build/niaok-analysis
print-build-config:
	@printf 'make_cc=%s\nmake_cflags=%s\nmake_ldlibs=%s\n' \
		'$(CC)' '$(CFLAGS)' '$(LDLIBS)'
clean:
	rm -f build/test_vc build/test_tree build/test_accumulator \
		build/prove_opening build/test_vc_p1 build/test_vc_p2 \
		build/test_vc_p3 build/benchmark_p1 build/benchmark_p2 \
		build/benchmark_p3 build/niaok_trace_p1 build/niaok_trace_p2 \
		build/niaok_trace_p3 build/labrador/data-source.h \
		build/labrador/data.h build/labrador/labrador-source.c \
		build/labrador/labrador.c build/labrador/poly-source.c \
		build/labrador/poly.c build/labrador/randombytes-source.c \
		build/labrador/randombytes.c build/labrador/chihuahua-source.c \
		build/labrador/chihuahua.c build/labrador/chihuahua.c.rej \
		build/labrador/polz-source.c build/labrador/polz.c \
		build/labrador/polz.c.rej

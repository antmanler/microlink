# Host harness for the interactive-login path (DESIGN section 10, probe P3).
#
#   make test    unit tests of the register codec, the login getters, the coord decisions,
#                the coord -> wg_mgr peer-update list, wireguard-lwip's handshake
#                trigger and give-up, and the DISCO box key (nacl_box.c vector and the
#                per-peer key cache)
#   make probe   build the P3 probe
#   make run     run the probe against the real control server (keyless register;
#                prints states only, never the login URL)
#
# The firmware sources compile unchanged. Only the FreeRTOS / lwIP / ESP headers
# are shims (shim/); mbedtls and cJSON come from ESP-IDF's own source tree.

IDF_PATH ?= $(HOME)/esp/esp-idf-v5.5.3
HERE     := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ML       := $(HERE)/../../components/microlink
WG       := $(ML)/components/wireguard_lwip/src
MBEDTLS  := $(IDF_PATH)/components/mbedtls/mbedtls
CJSON    := $(IDF_PATH)/components/json/cJSON
LWIP_INC := $(IDF_PATH)/components/lwip/lwip/src/include
OUT      := $(HERE)/build

CC       ?= cc
CFLAGS   ?= -std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare
INCLUDES := -I$(HERE)/shim -I$(ML)/include -I$(ML)/src -I$(WG) -I$(WG)/crypto/refc \
            -I$(CJSON) -I$(MBEDTLS)/include -I$(MBEDTLS)/library
LDLIBS   := -lm

MBED_SRC := chacha20 chachapoly poly1305 platform_util platform constant_time base64
LIB_SRC  := $(ML)/src/ml_register.c $(ML)/src/ml_login.c $(ML)/src/ml_h2.c $(ML)/src/ml_noise.c \
            $(ML)/src/ml_netcheck.c $(ML)/src/ml_peer_policy.c $(ML)/src/ml_peer_updates.c \
            $(ML)/src/x25519.c $(WG)/crypto/refc/blake2s.c $(CJSON)/cJSON.c \
            $(addprefix $(MBEDTLS)/library/,$(addsuffix .c,$(MBED_SRC))) $(HERE)/host_stubs.c

.PHONY: all test probe run clean
all: test probe

$(OUT):
	mkdir -p $(OUT)

# Each .c is compiled separately; ml_coord.c is #included by probe.c, so probe.c
# needs no other copy of it.
$(OUT)/test_codec: $(HERE)/test_codec.c $(LIB_SRC) | $(OUT)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(HERE)/test_codec.c $(LIB_SRC) $(LDLIBS)

$(OUT)/test_coord: $(HERE)/test_coord.c $(ML)/src/ml_coord.c $(LIB_SRC) | $(OUT)
	$(CC) $(CFLAGS) $(INCLUDES) -I$(ML)/src -o $@ $(HERE)/test_coord.c $(LIB_SRC) $(LDLIBS)

$(OUT)/probe: $(HERE)/probe.c $(ML)/src/ml_coord.c $(LIB_SRC) | $(OUT)
	$(CC) $(CFLAGS) $(INCLUDES) -I$(ML)/src -o $@ $(HERE)/probe.c $(LIB_SRC) $(LDLIBS)

test: $(OUT)/test_codec $(OUT)/test_coord $(OUT)/test_wg $(OUT)/test_peer_updates $(OUT)/test_disco_key
	$(OUT)/test_codec
	$(OUT)/test_coord
	$(OUT)/test_wg
	$(OUT)/test_peer_updates
	$(OUT)/test_disco_key

# nacl_box.c against the NaCl vector, and the per-peer key cache (ml_disco_key.c, included by
# the test so the X25519 calls can be counted), under AddressSanitizer and UBSan. The real
# nacl_box.c, x25519.c and mbedtls platform_util.c; no other firmware source.
$(OUT)/test_disco_key: $(HERE)/test_disco_key.c $(ML)/src/ml_disco_key.c $(ML)/src/nacl_box.c \
                       $(ML)/src/x25519.c $(MBEDTLS)/library/platform_util.c | $(OUT)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer $(INCLUDES) \
	    -o $@ $(HERE)/test_disco_key.c $(ML)/src/nacl_box.c $(ML)/src/x25519.c \
	    $(MBEDTLS)/library/platform_util.c $(LDLIBS)

# The peer-update list alone, under AddressSanitizer and UBSan (a double free or a use
# after free aborts; LeakSanitizer adds leak reports where the platform has it). The test
# includes ml_peer_updates.c itself, to count frees and to make the lock a real mutex.
$(OUT)/test_peer_updates: $(HERE)/test_peer_updates.c $(ML)/src/ml_peer_updates.c | $(OUT)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -pthread $(INCLUDES) \
	    -o $@ $(HERE)/test_peer_updates.c $(LDLIBS)

# wireguard-lwip against IDF's lwIP headers (shim-lwip/ holds the options; test_wg.c
# supplies the lwIP functions it links). No MicroLink shims on this include path.
WG_CRYPTO := $(addprefix $(WG)/crypto/refc/,blake2s.c chacha20.c chacha20poly1305.c poly1305-donna.c x25519.c)
$(OUT)/test_wg: $(HERE)/test_wg.c $(WG)/wireguardif.c $(WG)/wireguard.c $(WG)/crypto.c | $(OUT)
	$(CC) $(CFLAGS) -Wno-macro-redefined -Wno-unused-function -Wno-unused-variable \
	    -Wno-unknown-warning-option -Wno-unterminated-string-initialization -DWIREGUARD_CRYPTO_REFC=1 \
	    -I$(HERE)/shim-lwip -I$(LWIP_INC) -I$(WG) -I$(WG)/crypto/refc -o $@ $(HERE)/test_wg.c $(WG_CRYPTO)

probe: $(OUT)/probe

run: $(OUT)/probe
	$(OUT)/probe $(ARGS)

clean:
	rm -rf $(OUT)

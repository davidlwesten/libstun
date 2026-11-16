/* Generated from stun.pkt -- do not edit.
 *
 * libFuzzer harness for the code in stun_wire_gen.c. Each input is used twice:
 * as a packet to decode (decode_<message>), and as a recipe for building
 * a valid message to encode (encode_<message>).
 *
 *   clang -std=c23 -g -fsanitize=fuzzer,address,undefined \
 *       stun_wire_fuzz.c stun_wire_gen.c -o stun_wire_fuzz
 */
#include <stdlib.h>
#include <string.h>

#include "stun_wire_gen.h"

/* Recipe input: choices are read from [p, end); past the end, they are 0. */
struct src {
    const uint8_t *p;
    const uint8_t *end;
};

static uint8_t take_u8(struct src *in) {
    return in->p < in->end ? *in->p++ : 0;
}

static uint32_t take_u32(struct src *in) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++)
        v = v << 8 | take_u8(in);
    return v;
}

static void take_raw(struct src *in, uint8_t *dst, size_t n) {
    for (size_t i = 0; i < n; i++)
        dst[i] = take_u8(in);
}

/* Storage for list items and strings built from one recipe. */
static alignas(max_align_t) uint8_t arena[1 << 16];
static size_t arena_used;

static void *arena_alloc(size_t n) {
    size_t a = alignof(max_align_t);
    size_t at = (arena_used + a - 1) / a * a;
    if (n == 0 || n > sizeof arena - at)
        return NULL;
    arena_used = at + n;
    return arena + at;
}

static volatile uint8_t sink;

static void walk_bytes(const struct stun_wire_bytes *v) {
    if (v->len != 0)
        sink = v->ptr[v->len - 1];
}

/* A view into the recipe itself: up to max bytes, as many as remain. */
static void take_bytes(struct src *in, struct stun_wire_bytes *v, size_t max) {
    size_t n = (size_t)take_u8(in) << 8 | take_u8(in);
    size_t left = (size_t)(in->end - in->p);
    n = n % (max < SIZE_MAX ? max + 1 : SIZE_MAX);
    v->len = n < left ? n : left;
    v->ptr = in->p;
    in->p += v->len;
}

static void walk_attribute(const struct stun_wire_attribute *v) {
    walk_bytes(&v->value);
}

static void walk_message(const struct stun_wire_message *v) {
    {
        struct stun_wire_attribute_iter it;
        struct stun_wire_attribute item;
        stun_wire_attribute_iter_init(&it, &v->attributes);
        while (stun_wire_attribute_iter_next(&it, &item))
            walk_attribute(&item);
    }
}

static void walk_ipv4(const struct stun_wire_ipv4 *v) {
    (void)v;
}

static void walk_ipv6(const struct stun_wire_ipv6 *v) {
    (void)v;
}

static void walk_xor_mapped_address(const struct stun_wire_xor_mapped_address *v) {
    switch (v->family) {
    case STUN_WIRE_FAMILY_IPV4:
        walk_ipv4(&v->address.ipv4);
        break;
    case STUN_WIRE_FAMILY_IPV6:
        walk_ipv6(&v->address.ipv6);
        break;
    default:
        break;
    }
}

static void build_attribute(struct src *in, struct stun_wire_attribute *v) {
    v->type = (uint16_t)(take_u32(in) & 0xffff);
    take_bytes(in, &v->value, 0xffff);
}

static void build_message(struct src *in, struct stun_wire_message *v) {
    v->type = (uint16_t)(take_u32(in) & 0x3fff);
    take_raw(in, v->transaction_id, 12);
    {
        size_t n = take_u8(in) % 4;
        struct stun_wire_attribute *items = arena_alloc(n * sizeof *items);
        if (items == NULL)
            n = 0;
        for (size_t i = 0; i < n; i++)
            build_attribute(in, &items[i]);
        struct stun_wire_attribute_list list = { .items = items, .count = n };
        v->attributes = list;
    }
}

static void build_ipv4(struct src *in, struct stun_wire_ipv4 *v) {
    take_raw(in, v->addr, 4);
}

static void build_ipv6(struct src *in, struct stun_wire_ipv6 *v) {
    take_raw(in, v->addr, 16);
}

static void build_xor_mapped_address(struct src *in, struct stun_wire_xor_mapped_address *v) {
    v->family = (enum stun_wire_family)(take_u32(in) & 0xff);
    v->port = (uint16_t)(take_u32(in) & 0xffff);
    switch (take_u8(in) % 2) {
    case 0:
        v->family = STUN_WIRE_FAMILY_IPV4;
        build_ipv4(in, &v->address.ipv4);
        break;
    default:
        v->family = STUN_WIRE_FAMILY_IPV6;
        build_ipv6(in, &v->address.ipv6);
        break;
    }
}

/* Decode then encode must give back the input exactly. */
static void decode_message(const uint8_t *buf, size_t size) {
    struct stun_wire_message msg;
    if (stun_wire_message_decode(&msg, buf, size) != STUN_WIRE_OK)
        return;
    walk_message(&msg);
    if (stun_wire_message_encoded_size(&msg) != size)
        abort();
    uint8_t *a = malloc(size != 0 ? size : 1);
    uint8_t *b = malloc(size != 0 ? size : 1);
    size_t n = 0;
    if (stun_wire_message_encode(&msg, a, size, &n) != STUN_WIRE_OK || n != size)
        abort();
    if (size != 0 &&
        stun_wire_message_encode(&msg, b, size - 1, &n) != STUN_WIRE_NOSPACE)
        abort();
    if (memcmp(a, buf, size) != 0)
        abort();
    free(a);
    free(b);
}

/* Build a valid Message from the input, then encode it: it must take
 * exactly encoded_size bytes, decode, and encode to identical bytes. */
static void encode_message(const uint8_t *data, size_t len) {
    struct src in = { data, data + len };
    struct stun_wire_message msg = {};
    arena_used = 0;
    build_message(&in, &msg);
    size_t size = stun_wire_message_encoded_size(&msg);
    size_t n = 0;
    if (size > STUN_WIRE_MESSAGE_MAX_SIZE) {
        if (stun_wire_message_encode(&msg, NULL, 0, &n) != STUN_WIRE_INVALID)
            abort();
        return;
    }
    uint8_t *a = malloc(size != 0 ? size : 1);
    uint8_t *b = malloc(size != 0 ? size : 1);
    if (stun_wire_message_encode(&msg, a, size, &n) != STUN_WIRE_OK || n != size)
        abort();
    struct stun_wire_message back;
    if (stun_wire_message_decode(&back, a, size) != STUN_WIRE_OK)
        abort();
    if (stun_wire_message_encode(&back, b, size, &n) != STUN_WIRE_OK || n != size ||
        memcmp(a, b, size) != 0)
        abort();
    free(a);
    free(b);
}

/* XorMappedAddress has reserved fields or padding, which decode ignores and
 * encode writes as zeros, so the first encode may differ from the
 * input there. It must still have the same length, decode again, and
 * encode to identical bytes. */
static void decode_xor_mapped_address(const uint8_t *buf, size_t size) {
    struct stun_wire_xor_mapped_address msg;
    if (stun_wire_xor_mapped_address_decode(&msg, buf, size) != STUN_WIRE_OK)
        return;
    walk_xor_mapped_address(&msg);
    if (stun_wire_xor_mapped_address_encoded_size(&msg) != size)
        abort();
    uint8_t *a = malloc(size != 0 ? size : 1);
    uint8_t *b = malloc(size != 0 ? size : 1);
    size_t n = 0;
    if (stun_wire_xor_mapped_address_encode(&msg, a, size, &n) != STUN_WIRE_OK || n != size)
        abort();
    if (size != 0 &&
        stun_wire_xor_mapped_address_encode(&msg, b, size - 1, &n) != STUN_WIRE_NOSPACE)
        abort();
    struct stun_wire_xor_mapped_address again;
    if (stun_wire_xor_mapped_address_decode(&again, a, size) != STUN_WIRE_OK)
        abort();
    if (stun_wire_xor_mapped_address_encode(&again, b, size, &n) != STUN_WIRE_OK || n != size ||
        memcmp(a, b, size) != 0)
        abort();
    free(a);
    free(b);
}

/* Build a valid XorMappedAddress from the input, then encode it: it must take
 * exactly encoded_size bytes, decode, and encode to identical bytes. */
static void encode_xor_mapped_address(const uint8_t *data, size_t len) {
    struct src in = { data, data + len };
    struct stun_wire_xor_mapped_address msg = {};
    arena_used = 0;
    build_xor_mapped_address(&in, &msg);
    size_t size = stun_wire_xor_mapped_address_encoded_size(&msg);
    size_t n = 0;
    if (size > STUN_WIRE_XOR_MAPPED_ADDRESS_MAX_SIZE) {
        if (stun_wire_xor_mapped_address_encode(&msg, NULL, 0, &n) != STUN_WIRE_INVALID)
            abort();
        return;
    }
    uint8_t *a = malloc(size != 0 ? size : 1);
    uint8_t *b = malloc(size != 0 ? size : 1);
    if (stun_wire_xor_mapped_address_encode(&msg, a, size, &n) != STUN_WIRE_OK || n != size)
        abort();
    struct stun_wire_xor_mapped_address back;
    if (stun_wire_xor_mapped_address_decode(&back, a, size) != STUN_WIRE_OK)
        abort();
    if (stun_wire_xor_mapped_address_encode(&back, b, size, &n) != STUN_WIRE_OK || n != size ||
        memcmp(a, b, size) != 0)
        abort();
    free(a);
    free(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* An exact-size heap copy, so ASan catches any overread. */
    uint8_t *buf = malloc(size != 0 ? size : 1);
    if (size != 0)
        memcpy(buf, data, size);
    decode_message(buf, size);
    encode_message(buf, size);
    decode_xor_mapped_address(buf, size);
    encode_xor_mapped_address(buf, size);
    free(buf);
    return 0;
}

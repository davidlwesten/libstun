/* Generated from stun.pkt -- do not edit. */
#include "stun_wire_gen.h"

#include <string.h>

/* ---- wire primitives ---------------------------------------------------- */

/* Read cursor over [p, end). Every read checks bounds first. */
struct stun_wire_rd {
    const uint8_t *p;
    const uint8_t *end;
};

/* Write cursor over [p, end). */
struct stun_wire_wr {
    uint8_t *p;
    uint8_t *end;
};

static size_t stun_wire_rd_left(const struct stun_wire_rd *r) {
    return (size_t)(r->end - r->p);
}

static bool stun_wire_rd_u8(struct stun_wire_rd *r, uint8_t *v) {
    if (stun_wire_rd_left(r) < 1)
        return false;
    *v = r->p[0];
    r->p += 1;
    return true;
}

static bool stun_wire_rd_u16(struct stun_wire_rd *r, uint16_t *v) {
    if (stun_wire_rd_left(r) < 2)
        return false;
    *v = (uint16_t)((uint16_t)r->p[0] << 8 | r->p[1]);
    r->p += 2;
    return true;
}

static bool stun_wire_rd_u32(struct stun_wire_rd *r, uint32_t *v) {
    if (stun_wire_rd_left(r) < 4)
        return false;
    *v = (uint32_t)r->p[0] << 24 | (uint32_t)r->p[1] << 16
       | (uint32_t)r->p[2] << 8 | r->p[3];
    r->p += 4;
    return true;
}

static bool stun_wire_rd_skip(struct stun_wire_rd *r, size_t n) {
    if (stun_wire_rd_left(r) < n)
        return false;
    r->p += n;
    return true;
}

static bool stun_wire_rd_raw(struct stun_wire_rd *r, uint8_t *dst, size_t n) {
    if (stun_wire_rd_left(r) < n)
        return false;
    memcpy(dst, r->p, n);
    r->p += n;
    return true;
}

/* Splits the next n bytes off r into sub. */
static bool stun_wire_rd_sub(struct stun_wire_rd *r, struct stun_wire_rd *sub, size_t n) {
    if (stun_wire_rd_left(r) < n)
        return false;
    sub->p = r->p;
    sub->end = r->p + n;
    r->p += n;
    return true;
}

static bool stun_wire_rd_bytes(struct stun_wire_rd *r, struct stun_wire_bytes *v, size_t n) {
    if (stun_wire_rd_left(r) < n)
        return false;
    v->ptr = r->p;
    v->len = n;
    r->p += n;
    return true;
}

static size_t stun_wire_wr_left(const struct stun_wire_wr *w) {
    return (size_t)(w->end - w->p);
}

static stun_wire_status stun_wire_wr_u8(struct stun_wire_wr *w, uint8_t v) {
    if (stun_wire_wr_left(w) < 1)
        return STUN_WIRE_NOSPACE;
    w->p[0] = v;
    w->p += 1;
    return STUN_WIRE_OK;
}

static stun_wire_status stun_wire_wr_u16(struct stun_wire_wr *w, uint16_t v) {
    if (stun_wire_wr_left(w) < 2)
        return STUN_WIRE_NOSPACE;
    w->p[0] = (uint8_t)(v >> 8);
    w->p[1] = (uint8_t)v;
    w->p += 2;
    return STUN_WIRE_OK;
}

static stun_wire_status stun_wire_wr_u32(struct stun_wire_wr *w, uint32_t v) {
    if (stun_wire_wr_left(w) < 4)
        return STUN_WIRE_NOSPACE;
    w->p[0] = (uint8_t)(v >> 24);
    w->p[1] = (uint8_t)(v >> 16);
    w->p[2] = (uint8_t)(v >> 8);
    w->p[3] = (uint8_t)v;
    w->p += 4;
    return STUN_WIRE_OK;
}

static stun_wire_status stun_wire_wr_raw(struct stun_wire_wr *w, const void *src, size_t n) {
    if (stun_wire_wr_left(w) < n)
        return STUN_WIRE_NOSPACE;
    if (n != 0)
        memcpy(w->p, src, n);
    w->p += n;
    return STUN_WIRE_OK;
}

static stun_wire_status stun_wire_wr_zero(struct stun_wire_wr *w, size_t n) {
    if (stun_wire_wr_left(w) < n)
        return STUN_WIRE_NOSPACE;
    if (n != 0)
        memset(w->p, 0, n);
    w->p += n;
    return STUN_WIRE_OK;
}

/* Zero bytes that pad n bytes to a multiple of align. */
static size_t stun_wire_pad_len(size_t n, size_t align) {
    return (align - n % align) % align;
}

#define STUN_WIRE_CHECK(cond) \
    do { \
        if (!(cond)) \
            return false; \
    } while (0)

#define STUN_WIRE_TRY(expr) \
    do { \
        stun_wire_status st_ = (expr); \
        if (st_ != STUN_WIRE_OK) \
            return st_; \
    } while (0)

/* ---- struct Attribute --------------------------------------------------- */

static bool stun_wire_attribute_read(struct stun_wire_rd *r,
                                     struct stun_wire_attribute *out) {
    STUN_WIRE_CHECK(stun_wire_rd_u16(r, &out->type));
    uint16_t value_len;
    STUN_WIRE_CHECK(stun_wire_rd_u16(r, &value_len));
    STUN_WIRE_CHECK(stun_wire_rd_bytes(r, &out->value, value_len));
    return stun_wire_rd_skip(r, stun_wire_pad_len(value_len, 4));
}

static stun_wire_status stun_wire_attribute_write(
    struct stun_wire_wr *w, const struct stun_wire_attribute *in) {
    STUN_WIRE_TRY(stun_wire_wr_u16(w, in->type));
    if (in->value.len > 0xffff)
        return STUN_WIRE_INVALID;
    STUN_WIRE_TRY(stun_wire_wr_u16(w, (uint16_t)(in->value.len)));
    STUN_WIRE_TRY(stun_wire_wr_raw(w, in->value.ptr, in->value.len));
    return stun_wire_wr_zero(w, stun_wire_pad_len(in->value.len, 4));
}

static size_t stun_wire_attribute_size(const struct stun_wire_attribute *in) {
    return 4 + in->value.len + stun_wire_pad_len(in->value.len, 4);
}

/* ---- Attribute[..] ------------------------------------------------------ */

/* Consumes the rest of r. Fails unless it is a whole number of Attributes. */
static bool stun_wire_attribute_list_read(
    struct stun_wire_rd *r, struct stun_wire_attribute_list *out) {
    const uint8_t *start = r->p;
    struct stun_wire_attribute tmp;
    while (r->p != r->end)
        if (!stun_wire_attribute_read(r, &tmp))
            return false;
    out->raw = start;
    out->raw_len = (size_t)(r->p - start);
    out->items = NULL;
    out->count = 0;
    return true;
}

static stun_wire_status stun_wire_attribute_list_write(
    struct stun_wire_wr *w, const struct stun_wire_attribute_list *in) {
    if (in->items != NULL) {
        for (size_t i = 0; i < in->count; i++)
            STUN_WIRE_TRY(stun_wire_attribute_write(w, &in->items[i]));
        return STUN_WIRE_OK;
    }
    if (in->raw_len == 0)
        return STUN_WIRE_OK;
    /* raw may have been filled in by hand: encode never emits bytes that
     * decode would reject. */
    struct stun_wire_rd r = { in->raw, in->raw + in->raw_len };
    struct stun_wire_attribute_list check;
    if (!stun_wire_attribute_list_read(&r, &check))
        return STUN_WIRE_INVALID;
    return stun_wire_wr_raw(w, in->raw, in->raw_len);
}

static size_t stun_wire_attribute_list_size(
    const struct stun_wire_attribute_list *in) {
    if (in->items == NULL)
        return in->raw_len;
    size_t n = 0;
    for (size_t i = 0; i < in->count; i++)
        n += stun_wire_attribute_size(&in->items[i]);
    return n;
}

void stun_wire_attribute_iter_init(
    struct stun_wire_attribute_iter *it,
    const struct stun_wire_attribute_list *list) {
    it->pos = list->raw;
    it->end = list->raw_len != 0 ? list->raw + list->raw_len : list->raw;
}

bool stun_wire_attribute_iter_next(struct stun_wire_attribute_iter *it,
                                   struct stun_wire_attribute *out) {
    if (it->pos == it->end)
        return false;
    struct stun_wire_rd r = { it->pos, it->end };
    if (!stun_wire_attribute_read(&r, out))
        return false;
    it->pos = r.p;
    return true;
}

/* ---- message Message ---------------------------------------------------- */

static bool stun_wire_message_read(struct stun_wire_rd *r,
                                   struct stun_wire_message *out) {
    uint16_t bits0;
    STUN_WIRE_CHECK(stun_wire_rd_u16(r, &bits0));
    STUN_WIRE_CHECK((bits0 >> 14) == 0);
    out->type = (uint16_t)(bits0 & 0x3fff);
    uint16_t attributes_len;
    STUN_WIRE_CHECK(stun_wire_rd_u16(r, &attributes_len));
    uint32_t bits2;
    STUN_WIRE_CHECK(stun_wire_rd_u32(r, &bits2));
    STUN_WIRE_CHECK(bits2 == 0x2112a442);
    STUN_WIRE_CHECK(stun_wire_rd_raw(r, out->transaction_id, 12));
    struct stun_wire_rd attributes_r;
    STUN_WIRE_CHECK(stun_wire_rd_sub(r, &attributes_r, attributes_len));
    return stun_wire_attribute_list_read(&attributes_r, &out->attributes);
}

static stun_wire_status stun_wire_message_write(
    struct stun_wire_wr *w, const struct stun_wire_message *in) {
    if (in->type > 0x3fff)
        return STUN_WIRE_INVALID;
    STUN_WIRE_TRY(stun_wire_wr_u16(w, (uint16_t)(in->type)));
    size_t attributes_len = stun_wire_attribute_list_size(&in->attributes);
    if (attributes_len > 0xffff)
        return STUN_WIRE_INVALID;
    STUN_WIRE_TRY(stun_wire_wr_u16(w, (uint16_t)(attributes_len)));
    STUN_WIRE_TRY(stun_wire_wr_u32(w, (uint32_t)(0x2112a442)));
    STUN_WIRE_TRY(stun_wire_wr_raw(w, in->transaction_id, 12));
    return stun_wire_attribute_list_write(w, &in->attributes);
}

static size_t stun_wire_message_size(const struct stun_wire_message *in) {
    return 20 + stun_wire_attribute_list_size(&in->attributes);
}

stun_wire_status stun_wire_message_decode(struct stun_wire_message *out,
                                          const uint8_t *buf, size_t len) {
    struct stun_wire_rd r = { buf, len != 0 ? buf + len : buf };
    /* The message must account for every byte of the input. */
    if (!stun_wire_message_read(&r, out) || r.p != r.end)
        return STUN_WIRE_INVALID;
    return STUN_WIRE_OK;
}

stun_wire_status stun_wire_message_encode(const struct stun_wire_message *in,
                                          uint8_t *buf, size_t cap,
                                          size_t *written) {
    struct stun_wire_wr w = { buf, cap != 0 ? buf + cap : buf };
    STUN_WIRE_TRY(stun_wire_message_write(&w, in));
    *written = (size_t)(w.p - buf);
    return STUN_WIRE_OK;
}

size_t stun_wire_message_encoded_size(const struct stun_wire_message *in) {
    return stun_wire_message_size(in);
}

/* ---- struct Ipv4 -------------------------------------------------------- */

static bool stun_wire_ipv4_read(struct stun_wire_rd *r,
                                struct stun_wire_ipv4 *out) {
    return stun_wire_rd_raw(r, out->addr, 4);
}

static stun_wire_status stun_wire_ipv4_write(struct stun_wire_wr *w,
                                             const struct stun_wire_ipv4 *in) {
    return stun_wire_wr_raw(w, in->addr, 4);
}

static size_t stun_wire_ipv4_size(const struct stun_wire_ipv4 *in) {
    (void)in;
    return 4;
}

/* ---- struct Ipv6 -------------------------------------------------------- */

static bool stun_wire_ipv6_read(struct stun_wire_rd *r,
                                struct stun_wire_ipv6 *out) {
    return stun_wire_rd_raw(r, out->addr, 16);
}

static stun_wire_status stun_wire_ipv6_write(struct stun_wire_wr *w,
                                             const struct stun_wire_ipv6 *in) {
    return stun_wire_wr_raw(w, in->addr, 16);
}

static size_t stun_wire_ipv6_size(const struct stun_wire_ipv6 *in) {
    (void)in;
    return 16;
}

/* ---- message XorMappedAddress ------------------------------------------- */

static bool stun_wire_xor_mapped_address_address_read(
    struct stun_wire_rd *r, struct stun_wire_xor_mapped_address *out) {
    switch (out->family) {
    case STUN_WIRE_FAMILY_IPV4:
        return stun_wire_ipv4_read(r, &out->address.ipv4);
    case STUN_WIRE_FAMILY_IPV6:
        return stun_wire_ipv6_read(r, &out->address.ipv6);
    default:
        return false; /* unknown tag */
    }
}

static stun_wire_status stun_wire_xor_mapped_address_address_write(
    struct stun_wire_wr *w, const struct stun_wire_xor_mapped_address *in) {
    switch (in->family) {
    case STUN_WIRE_FAMILY_IPV4:
        return stun_wire_ipv4_write(w, &in->address.ipv4);
    case STUN_WIRE_FAMILY_IPV6:
        return stun_wire_ipv6_write(w, &in->address.ipv6);
    default:
        return STUN_WIRE_INVALID; /* unknown tag */
    }
}

static size_t stun_wire_xor_mapped_address_address_size(
    const struct stun_wire_xor_mapped_address *in) {
    switch (in->family) {
    case STUN_WIRE_FAMILY_IPV4:
        return stun_wire_ipv4_size(&in->address.ipv4);
    case STUN_WIRE_FAMILY_IPV6:
        return stun_wire_ipv6_size(&in->address.ipv6);
    default:
        return 0; /* unknown tag: encode fails */
    }
}

static bool stun_wire_xor_mapped_address_read(
    struct stun_wire_rd *r, struct stun_wire_xor_mapped_address *out) {
    STUN_WIRE_CHECK(stun_wire_rd_skip(r, 1));
    STUN_WIRE_CHECK(stun_wire_rd_u8(r, &out->family));
    STUN_WIRE_CHECK(stun_wire_rd_u16(r, &out->port));
    return stun_wire_xor_mapped_address_address_read(r, out);
}

static stun_wire_status stun_wire_xor_mapped_address_write(
    struct stun_wire_wr *w, const struct stun_wire_xor_mapped_address *in) {
    STUN_WIRE_TRY(stun_wire_wr_zero(w, 1));
    STUN_WIRE_TRY(stun_wire_wr_u8(w, in->family));
    STUN_WIRE_TRY(stun_wire_wr_u16(w, in->port));
    return stun_wire_xor_mapped_address_address_write(w, in);
}

static size_t stun_wire_xor_mapped_address_size(
    const struct stun_wire_xor_mapped_address *in) {
    return 4 + stun_wire_xor_mapped_address_address_size(in);
}

stun_wire_status stun_wire_xor_mapped_address_decode(
    struct stun_wire_xor_mapped_address *out, const uint8_t *buf, size_t len) {
    struct stun_wire_rd r = { buf, len != 0 ? buf + len : buf };
    /* The message must account for every byte of the input. */
    if (!stun_wire_xor_mapped_address_read(&r, out) || r.p != r.end)
        return STUN_WIRE_INVALID;
    return STUN_WIRE_OK;
}

stun_wire_status stun_wire_xor_mapped_address_encode(
    const struct stun_wire_xor_mapped_address *in, uint8_t *buf, size_t cap,
    size_t *written) {
    struct stun_wire_wr w = { buf, cap != 0 ? buf + cap : buf };
    STUN_WIRE_TRY(stun_wire_xor_mapped_address_write(&w, in));
    *written = (size_t)(w.p - buf);
    return STUN_WIRE_OK;
}

size_t stun_wire_xor_mapped_address_encoded_size(
    const struct stun_wire_xor_mapped_address *in) {
    return stun_wire_xor_mapped_address_size(in);
}

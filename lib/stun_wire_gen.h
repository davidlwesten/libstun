/* Generated from stun.pkt -- do not edit. */
#ifndef STUN_WIRE_GEN_H
#define STUN_WIRE_GEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    STUN_WIRE_OK = 0,
    /* decode: malformed or truncated input;
     * encode: unencodable input (unknown tag, value too wide for its field,
     *         NUL in cstr, message over its declared maximum size) */
    STUN_WIRE_INVALID,
    /* encode: output buffer too small */
    STUN_WIRE_NOSPACE,
} stun_wire_status;

/* Constants from stun.pkt. */
constexpr uint32_t STUN_WIRE_MAGIC_COOKIE = 0x2112A442;

/* enum Family : u8 */
enum stun_wire_family : uint8_t {
    STUN_WIRE_FAMILY_IPV4 = 1,
    STUN_WIRE_FAMILY_IPV6 = 2,
};

/* u8[..] and u8[len]: points into the buffer. */
struct stun_wire_bytes {
    const uint8_t *ptr;
    size_t len;
};

/* struct Attribute { type: u16; length: u16; value: u8[length] pad 4; } */
struct stun_wire_attribute {
    uint16_t type;
    struct stun_wire_bytes value;
};

/* Attribute[..]
 * decode: raw/raw_len cover the validated wire bytes; walk them with
 *         stun_wire_attribute_iter. items is NULL.
 * encode: if items is non-NULL, the count entries are written;
 *         otherwise raw is copied as-is (so decode -> encode round-trips). */
struct stun_wire_attribute_list {
    const uint8_t *raw;
    size_t raw_len;
    const struct stun_wire_attribute *items;
    size_t count;
};

struct stun_wire_attribute_iter {
    const uint8_t *pos;
    const uint8_t *end;
};

/* message Message {
 *     zero: u2 = 0;
 *     type: u14;
 *     length: u16;
 *     cookie: u32 = 0x2112a442;
 *     transaction_id: u8[12];
 *     attributes: Attribute[length];
 * } */
struct stun_wire_message {
    uint16_t type;
    uint8_t transaction_id[12];
    struct stun_wire_attribute_list attributes;
};

/* Size limits of an encoded Message, in bytes. */
constexpr size_t STUN_WIRE_MESSAGE_MIN_SIZE = 20;
constexpr size_t STUN_WIRE_MESSAGE_MAX_SIZE = 65555;

/* struct Ipv4 { addr: u8[4]; } */
struct stun_wire_ipv4 {
    uint8_t addr[4];
};

/* struct Ipv6 { addr: u8[16]; } */
struct stun_wire_ipv6 {
    uint8_t addr[16];
};

/* message XorMappedAddress {
 *     _: u8;
 *     family: Family;
 *     port: u16;
 *     address: switch (family) { ... };
 * } */
struct stun_wire_xor_mapped_address {
    enum stun_wire_family family;  /* selects address */
    uint16_t port;
    union {
        struct stun_wire_ipv4 ipv4;  /* IPV4 */
        struct stun_wire_ipv6 ipv6;  /* IPV6 */
    } address;
};

/* Size limits of an encoded XorMappedAddress, in bytes. */
constexpr size_t STUN_WIRE_XOR_MAPPED_ADDRESS_MIN_SIZE = 8;
constexpr size_t STUN_WIRE_XOR_MAPPED_ADDRESS_MAX_SIZE = 20;

/* Decode one Message. Views in *out borrow buf: keep buf alive and
 * unchanged while using them. */
stun_wire_status stun_wire_message_decode(struct stun_wire_message *out,
                                          const uint8_t *buf, size_t len);

/* Encode into buf[0..cap). On STUN_WIRE_OK, *written is the encoded length. */
stun_wire_status stun_wire_message_encode(const struct stun_wire_message *in,
                                          uint8_t *buf, size_t cap,
                                          size_t *written);

/* Exact number of bytes stun_wire_message_encode will write, if it succeeds. */
size_t stun_wire_message_encoded_size(const struct stun_wire_message *in);

/* Decode one XorMappedAddress. Views in *out borrow buf: keep buf alive and
 * unchanged while using them. */
stun_wire_status stun_wire_xor_mapped_address_decode(
    struct stun_wire_xor_mapped_address *out, const uint8_t *buf, size_t len);

/* Encode into buf[0..cap). On STUN_WIRE_OK, *written is the encoded length. */
stun_wire_status stun_wire_xor_mapped_address_encode(
    const struct stun_wire_xor_mapped_address *in, uint8_t *buf, size_t cap,
    size_t *written);

/* Exact number of bytes stun_wire_xor_mapped_address_encode will write, if it succeeds. */
size_t stun_wire_xor_mapped_address_encoded_size(
    const struct stun_wire_xor_mapped_address *in);

/* Iterate a decoded Attribute[..]. Decode already validated it,
 * so next() only returns false at the end. */
void stun_wire_attribute_iter_init(
    struct stun_wire_attribute_iter *it,
    const struct stun_wire_attribute_list *list);
bool stun_wire_attribute_iter_next(struct stun_wire_attribute_iter *it,
                                   struct stun_wire_attribute *out);

#endif

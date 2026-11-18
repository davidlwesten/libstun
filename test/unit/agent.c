#include <unity.h>

#include <byo/stun/stun.h>

#include <errno.h>
#include <string.h>

#include "runner.h"

static stun_agent_t *agent;

static uint8_t next_random;
static bool rng_fails;

// a counter, so every transaction ID differs
static bool fill(void * /*ctx*/, size_t size, uint8_t data[]) {
  if (rng_fails) {
    return false;
  }
  for (size_t i = 0; i < size; ++i) {
    data[i] = next_random++;
  }
  return true;
}

static void begin(uint16_t capacity) {
  next_random = 0;
  rng_fails = false;
  agent = stun_agent_begin(
      (stun_config_t){.rng = {.fill = fill}, .capacity = capacity});
  TEST_ASSERT_NOT_NULL(agent);
}

static stun_handle_t request() {
  auto const handle = stun_agent_binding_request(agent);
  TEST_ASSERT_TRUE(handle.has_value);
  TEST_ASSERT_NOT_EQUAL(0, handle.value);
  return handle.value;
}

typedef struct transaction_id {
  uint8_t bytes[12];
} transaction_id_t;

// a Binding request, returning its transaction ID
static transaction_id_t expect_send(stun_time_ms_t now) {
  auto const event = stun_agent_poll(agent, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_SEND, event.type);
  TEST_ASSERT_EQUAL_size_t(20, event.send.size);
  uint8_t const header[] = {0x00, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(header, event.send.data, sizeof(header));

  transaction_id_t id;
  memcpy(id.bytes, event.send.data + 8, sizeof(id.bytes));
  return id;
}

// 192.0.2.1:32853
static uint8_t const xor_mapped_address[] = {
    0x00, 0x20, 0, 8, 0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43};

// a Binding response, or another message of the same shape
static void receive(uint8_t const type[2],
                    transaction_id_t id,
                    size_t size,
                    uint8_t const attributes[]) {
  uint8_t data[64];
  TEST_ASSERT_LESS_OR_EQUAL_size_t(sizeof(data) - 20, size);
  uint8_t const header[] = {type[0], type[1], 0,    (uint8_t)size,
                            0x21,    0x12,    0xA4, 0x42};
  memcpy(data, header, sizeof(header));
  memcpy(data + 8, id.bytes, sizeof(id.bytes));
  memcpy(data + 20, attributes, size);
  stun_agent_on_datagram(agent, 20 + size, data);
}

static uint8_t const binding_success[] = {0x01, 0x01};

// a Binding success response mapping 192.0.2.1:32853
static void respond(transaction_id_t id) {
  receive(binding_success, id, sizeof(xor_mapped_address), xor_mapped_address);
}

static void expect_timeout(stun_time_ms_t now, stun_time_ms_t deadline) {
  auto const event = stun_agent_poll(agent, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_TIMEOUT, event.type);
  TEST_ASSERT_TRUE(event.timeout.deadline.has_value);
  TEST_ASSERT_EQUAL_UINT64(deadline, event.timeout.deadline.value);
}

static void expect_idle(stun_time_ms_t now) {
  auto const event = stun_agent_poll(agent, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_TIMEOUT, event.type);
  TEST_ASSERT_FALSE(event.timeout.deadline.has_value);
}

static void expect_bound(stun_time_ms_t now, stun_handle_t handle) {
  auto const event = stun_agent_poll(agent, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_BOUND, event.type);
  TEST_ASSERT_EQUAL_UINT16(handle, event.bound.handle);
  uint8_t const ip[16] = {[10] = 0xFF, 0xFF, 192, 0, 2, 1};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, event.bound.mapped.ip.addr, sizeof(ip));
  TEST_ASSERT_EQUAL_UINT16(32853, event.bound.mapped.port);
}

static void
expect_failed(stun_time_ms_t now, stun_handle_t handle, stun_failure_t reason) {
  auto const event = stun_agent_poll(agent, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_FAILED, event.type);
  TEST_ASSERT_EQUAL_UINT16(handle, event.failed.handle);
  TEST_ASSERT_EQUAL(reason, event.failed.reason);
}

static void expect_error_response(stun_time_ms_t now,
                                  stun_handle_t handle,
                                  uint16_t error_code) {
  auto const event = stun_agent_poll(agent, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_FAILED, event.type);
  TEST_ASSERT_EQUAL_UINT16(handle, event.failed.handle);
  TEST_ASSERT_EQUAL(STUN_FAILURE_ERROR_RESPONSE, event.failed.reason);
  TEST_ASSERT_EQUAL_UINT16(error_code, event.failed.error_code);
}

static void test_agent_nothing_requested() {
  begin(0);
  expect_idle(0);
  stun_agent_end(agent);
}

static void test_agent_binding() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(1000);
  expect_timeout(1000, 1500);
  respond(id);

  expect_bound(1010, handle);
  expect_idle(1010);
  stun_agent_end(agent);
}

static void test_agent_retransmits_until_it_gives_up() {
  begin(0);
  auto const handle = request();

  // the same transaction each time, at 0, 0.5, 1.5, 3.5, 7.5, 15.5, 31.5 s
  stun_time_ms_t const sends[] = {0, 500, 1500, 3500, 7500, 15500, 31500};
  auto const id = expect_send(sends[0]);
  for (size_t i = 1; i < 7; ++i) {
    expect_timeout(sends[i] - 1, sends[i]);
    auto const again = expect_send(sends[i]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(id.bytes, again.bytes, sizeof(id.bytes));
  }

  expect_timeout(39499, 39500);
  expect_failed(39500, handle, STUN_FAILURE_TIMEOUT);
  expect_idle(39500);
  stun_agent_end(agent);
}

static void test_agent_answer_to_a_retransmission() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(0);
  expect_send(500);
  respond(id);
  // the server answered both
  respond(id);

  expect_bound(600, handle);
  expect_idle(600);
  stun_agent_end(agent);
}

static void test_agent_requests_in_flight_together() {
  begin(0);
  auto const first = request();
  auto const second = request();
  TEST_ASSERT_NOT_EQUAL(first, second);

  auto const first_id = expect_send(0);
  auto const second_id = expect_send(0);
  TEST_ASSERT_FALSE(memcmp(first_id.bytes, second_id.bytes, 12) == 0);
  expect_timeout(0, 500);

  respond(second_id);
  expect_bound(10, second);
  expect_timeout(10, 500);

  respond(first_id);
  expect_bound(20, first);
  expect_idle(20);
  stun_agent_end(agent);
}

static void test_agent_ignores_unknown_transactions() {
  begin(0);
  request();
  auto id = expect_send(0);
  id.bytes[0] ^= 1;
  respond(id);

  expect_timeout(10, 500);
  stun_agent_end(agent);
}

static void test_agent_first_address_counts() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(0);

  // then 198.51.100.1:32853
  uint8_t const attributes[] = {
      0x00, 0x20, 0, 8, 0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43,
      0x00, 0x20, 0, 8, 0x00, 0x01, 0xA1, 0x47, 0xE7, 0x21, 0xC0, 0x43,
  };
  receive(binding_success, id, sizeof(attributes), attributes);

  expect_bound(10, handle);
  stun_agent_end(agent);
}

static void test_agent_skips_optional_attributes() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(0);

  uint8_t const attributes[] = {
      0x80, 0x22, 0, 3, 'a',  'b',  'c',  0, // SOFTWARE, padded
      0x00, 0x20, 0, 8, 0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43,
  };
  receive(binding_success, id, sizeof(attributes), attributes);

  expect_bound(10, handle);
  stun_agent_end(agent);
}

static void test_agent_fails_on_unusable_responses() {
  begin(0);
  auto const required = request();
  auto const required_after = request();
  auto const missing = request();
  auto const family = request();
  auto const required_id = expect_send(0);
  auto const required_after_id = expect_send(0);
  auto const missing_id = expect_send(0);
  auto const family_id = expect_send(0);

  // an attribute we'd have to understand
  uint8_t const unknown[] = {
      0x7F, 0xFF, 0,    4,    1,    2,    3,    4,    0x00, 0x20,
      0,    8,    0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43,
  };
  receive(binding_success, required_id, sizeof(unknown), unknown);

  // the same after the address
  uint8_t const unknown_after[] = {
      0x00, 0x20, 0,    8,    0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12,
      0xA6, 0x43, 0x7F, 0xFF, 0,    4,    1,    2,    3,    4,
  };
  receive(binding_success, required_after_id, sizeof(unknown_after),
          unknown_after);

  // no address
  receive(binding_success, missing_id, 0, unknown);

  // an address of an unknown family
  uint8_t const unknown_family[] = {0x00, 0x20, 0,    8,    0x00, 0x03,
                                    0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43};
  receive(binding_success, family_id, sizeof(unknown_family), unknown_family);

  expect_failed(10, required, STUN_FAILURE_INVALID_RESPONSE);
  expect_failed(10, required_after, STUN_FAILURE_INVALID_RESPONSE);
  expect_failed(10, missing, STUN_FAILURE_INVALID_RESPONSE);
  expect_failed(10, family, STUN_FAILURE_INVALID_RESPONSE);
  expect_idle(10);
  stun_agent_end(agent);
}

static void test_agent_first_answer_decides() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(0);
  expect_send(500);
  receive(binding_success, id, 0, xor_mapped_address);
  respond(id);

  expect_failed(600, handle, STUN_FAILURE_INVALID_RESPONSE);
  expect_idle(600);
  stun_agent_end(agent);
}

static uint8_t const binding_error[] = {0x01, 0x11};

// 400 Bad Request, padded
#define ERROR_CODE_400                                                         \
  0x00, 0x09, 0, 15, 0, 0, 4, 0, 'B', 'a', 'd', ' ', 'R', 'e', 'q', 'u', 'e',  \
      's', 't', 0

static void test_agent_error_response() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(0);

  uint8_t const attributes[] = {
      ERROR_CODE_400, 0x80, 0x22, 0, 3, 'a', 'b', 'c', 0, // SOFTWARE, padded
  };
  receive(binding_error, id, sizeof(attributes), attributes);

  expect_error_response(10, handle, STUN_ERROR_BAD_REQUEST);
  expect_idle(10);
  stun_agent_end(agent);
}

static void test_agent_fails_on_unusable_error_responses() {
  begin(0);
  auto const missing = request();
  auto const invalid = request();
  auto const required = request();
  auto const missing_id = expect_send(0);
  auto const invalid_id = expect_send(0);
  auto const required_id = expect_send(0);

  // no ERROR-CODE
  receive(binding_error, missing_id, 0, xor_mapped_address);

  // a class above 6
  uint8_t const class_7[] = {0x00, 0x09, 0, 4, 0, 0, 7, 0};
  receive(binding_error, invalid_id, sizeof(class_7), class_7);

  // an attribute we'd have to understand
  uint8_t const unknown[] = {ERROR_CODE_400, 0x7F, 0xFF, 0, 4, 1, 2, 3, 4};
  receive(binding_error, required_id, sizeof(unknown), unknown);

  expect_failed(10, missing, STUN_FAILURE_INVALID_RESPONSE);
  expect_failed(10, invalid, STUN_FAILURE_INVALID_RESPONSE);
  expect_failed(10, required, STUN_FAILURE_INVALID_RESPONSE);
  expect_idle(10);
  stun_agent_end(agent);
}

static void test_agent_ignores_other_messages() {
  begin(0);
  request();
  auto const id = expect_send(0);

  // other classes and methods with the same transaction ID
  uint8_t const binding_request[] = {0x00, 0x01};
  receive(binding_request, id, sizeof(xor_mapped_address), xor_mapped_address);
  uint8_t const other_success[] = {0x01, 0x02};
  receive(other_success, id, sizeof(xor_mapped_address), xor_mapped_address);
  uint8_t const other_error[] = {0x01, 0x12};
  uint8_t const error_code[] = {ERROR_CODE_400};
  receive(other_error, id, sizeof(error_code), error_code);

  expect_timeout(10, 500);
  stun_agent_end(agent);
}

static void test_agent_ignores_garbage() {
  begin(0);
  request();
  expect_send(0);
  uint8_t const data[] = {1, 2, 3};
  stun_agent_on_datagram(agent, sizeof(data), data);

  expect_timeout(10, 500);
  stun_agent_end(agent);
}

static void test_agent_at_capacity() {
  begin(2);
  request();
  auto const second = request();
  auto const full = stun_agent_binding_request(agent);
  TEST_ASSERT_FALSE(full.has_value);
  TEST_ASSERT_EQUAL_INT(ENOBUFS, full.error);

  // a slot frees up once its last event is polled
  expect_send(0);
  auto const id = expect_send(0);
  respond(id);
  TEST_ASSERT_FALSE(stun_agent_binding_request(agent).has_value);
  expect_bound(10, second);
  request();
  stun_agent_end(agent);
}

static void test_agent_handles_not_reused_right_away() {
  begin(1);
  auto const first = request();
  respond(expect_send(0));
  expect_bound(10, first);

  auto const second = request();
  TEST_ASSERT_NOT_EQUAL(first, second);
  stun_agent_end(agent);
}

static void test_agent_rng_fails() {
  begin(0);
  rng_fails = true;
  auto const handle = stun_agent_binding_request(agent);
  TEST_ASSERT_FALSE(handle.has_value);
  TEST_ASSERT_EQUAL_INT(EIO, handle.error);
  expect_idle(0);
  stun_agent_end(agent);
}

static void test_agent_end_in_flight() {
  begin(0);
  request();
  expect_send(0);
  // nothing leaks, which ASan checks
  stun_agent_end(agent);
}

void agent_tests() {
  RUN_TEST(test_agent_nothing_requested);
  RUN_TEST(test_agent_binding);
  RUN_TEST(test_agent_retransmits_until_it_gives_up);
  RUN_TEST(test_agent_answer_to_a_retransmission);
  RUN_TEST(test_agent_requests_in_flight_together);
  RUN_TEST(test_agent_ignores_unknown_transactions);
  RUN_TEST(test_agent_first_address_counts);
  RUN_TEST(test_agent_skips_optional_attributes);
  RUN_TEST(test_agent_fails_on_unusable_responses);
  RUN_TEST(test_agent_first_answer_decides);
  RUN_TEST(test_agent_error_response);
  RUN_TEST(test_agent_fails_on_unusable_error_responses);
  RUN_TEST(test_agent_ignores_other_messages);
  RUN_TEST(test_agent_ignores_garbage);
  RUN_TEST(test_agent_at_capacity);
  RUN_TEST(test_agent_handles_not_reused_right_away);
  RUN_TEST(test_agent_rng_fails);
  RUN_TEST(test_agent_end_in_flight);
}

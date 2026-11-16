#include <unity.h>

#include <byo/stun/stun.h>

#include <errno.h>
#include <string.h>

#include "runner.h"

static stun_session_t *session;

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
  session = stun_session_begin(
      (stun_config_t){.rng = {.fill = fill}, .capacity = capacity});
  TEST_ASSERT_NOT_NULL(session);
}

static stun_handle_t request() {
  auto const handle = stun_session_binding_request(session);
  TEST_ASSERT_TRUE(handle.has_value);
  TEST_ASSERT_NOT_EQUAL(0, handle.value);
  return handle.value;
}

typedef struct transaction_id {
  uint8_t bytes[12];
} transaction_id_t;

// a Binding request, returning its transaction ID
static transaction_id_t expect_send(stun_time_ms_t now) {
  auto const event = stun_session_poll(session, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_SEND, event.type);
  TEST_ASSERT_EQUAL_size_t(20, event.send.size);
  uint8_t const header[] = {0x00, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(header, event.send.data, sizeof(header));

  transaction_id_t id;
  memcpy(id.bytes, event.send.data + 8, sizeof(id.bytes));
  return id;
}

// a Binding success response mapping 192.0.2.1:32853
static void respond(transaction_id_t id) {
  uint8_t const header[] = {0x01, 0x01, 0, 12, 0x21, 0x12, 0xA4, 0x42};
  uint8_t const xor_mapped_address[] = {0x00, 0x20, 0,    8,    0x00, 0x01,
                                        0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43};

  uint8_t data[32];
  memcpy(data, header, sizeof(header));
  memcpy(data + 8, id.bytes, sizeof(id.bytes));
  memcpy(data + 20, xor_mapped_address, sizeof(xor_mapped_address));
  stun_session_on_datagram(session, sizeof(data), data);
}

static void expect_timeout(stun_time_ms_t now, stun_time_ms_t deadline) {
  auto const event = stun_session_poll(session, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_TIMEOUT, event.type);
  TEST_ASSERT_TRUE(event.timeout.deadline.has_value);
  TEST_ASSERT_EQUAL_UINT64(deadline, event.timeout.deadline.value);
}

static void expect_idle(stun_time_ms_t now) {
  auto const event = stun_session_poll(session, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_TIMEOUT, event.type);
  TEST_ASSERT_FALSE(event.timeout.deadline.has_value);
}

static void expect_bound(stun_time_ms_t now, stun_handle_t handle) {
  auto const event = stun_session_poll(session, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_BOUND, event.type);
  TEST_ASSERT_EQUAL_UINT16(handle, event.bound.handle);
  uint8_t const ip[16] = {[10] = 0xFF, 0xFF, 192, 0, 2, 1};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, event.bound.mapped.ip.addr, sizeof(ip));
  TEST_ASSERT_EQUAL_UINT16(32853, event.bound.mapped.port);
}

static void expect_failed(stun_time_ms_t now, stun_handle_t handle) {
  auto const event = stun_session_poll(session, now);
  TEST_ASSERT_EQUAL(STUN_EVENT_FAILED, event.type);
  TEST_ASSERT_EQUAL_UINT16(handle, event.failed.handle);
}

static void test_session_nothing_requested() {
  begin(0);
  expect_idle(0);
  stun_session_end(session);
}

static void test_session_binding() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(1000);
  expect_timeout(1000, 1500);
  respond(id);

  expect_bound(1010, handle);
  expect_idle(1010);
  stun_session_end(session);
}

static void test_session_retransmits_until_it_gives_up() {
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
  expect_failed(39500, handle);
  expect_idle(39500);
  stun_session_end(session);
}

static void test_session_answer_to_a_retransmission() {
  begin(0);
  auto const handle = request();
  auto const id = expect_send(0);
  expect_send(500);
  respond(id);
  // the server answered both
  respond(id);

  expect_bound(600, handle);
  expect_idle(600);
  stun_session_end(session);
}

static void test_session_requests_in_flight_together() {
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
  stun_session_end(session);
}

static void test_session_ignores_unknown_transactions() {
  begin(0);
  request();
  auto id = expect_send(0);
  id.bytes[0] ^= 1;
  respond(id);

  expect_timeout(10, 500);
  stun_session_end(session);
}

static void test_session_ignores_garbage() {
  begin(0);
  request();
  expect_send(0);
  uint8_t const data[] = {1, 2, 3};
  stun_session_on_datagram(session, sizeof(data), data);

  expect_timeout(10, 500);
  stun_session_end(session);
}

static void test_session_at_capacity() {
  begin(2);
  request();
  auto const second = request();
  auto const full = stun_session_binding_request(session);
  TEST_ASSERT_FALSE(full.has_value);
  TEST_ASSERT_EQUAL_INT(ENOBUFS, full.error);

  // a slot frees up once its last event is polled
  expect_send(0);
  auto const id = expect_send(0);
  respond(id);
  TEST_ASSERT_FALSE(stun_session_binding_request(session).has_value);
  expect_bound(10, second);
  request();
  stun_session_end(session);
}

static void test_session_handles_not_reused_right_away() {
  begin(1);
  auto const first = request();
  respond(expect_send(0));
  expect_bound(10, first);

  auto const second = request();
  TEST_ASSERT_NOT_EQUAL(first, second);
  stun_session_end(session);
}

static void test_session_rng_fails() {
  begin(0);
  rng_fails = true;
  auto const handle = stun_session_binding_request(session);
  TEST_ASSERT_FALSE(handle.has_value);
  TEST_ASSERT_EQUAL_INT(EIO, handle.error);
  expect_idle(0);
  stun_session_end(session);
}

static void test_session_end_in_flight() {
  begin(0);
  request();
  expect_send(0);
  // nothing leaks, which ASan checks
  stun_session_end(session);
}

void session_tests() {
  RUN_TEST(test_session_nothing_requested);
  RUN_TEST(test_session_binding);
  RUN_TEST(test_session_retransmits_until_it_gives_up);
  RUN_TEST(test_session_answer_to_a_retransmission);
  RUN_TEST(test_session_requests_in_flight_together);
  RUN_TEST(test_session_ignores_unknown_transactions);
  RUN_TEST(test_session_ignores_garbage);
  RUN_TEST(test_session_at_capacity);
  RUN_TEST(test_session_handles_not_reused_right_away);
  RUN_TEST(test_session_rng_fails);
  RUN_TEST(test_session_end_in_flight);
}

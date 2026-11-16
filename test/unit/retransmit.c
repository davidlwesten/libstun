#include <unity.h>

#include "retransmit.h"
#include "runner.h"

static void test_retransmit_first_due_right_away() {
  stun_retransmit_t const retransmit = {};
  TEST_ASSERT_EQUAL(STUN_RETRANSMIT_DUE, stun_retransmit_poll(&retransmit, 0));
  TEST_ASSERT_EQUAL(STUN_RETRANSMIT_DUE,
                    stun_retransmit_poll(&retransmit, 123456));
}

static void test_retransmit_doubles_from_500ms() {
  stun_retransmit_t retransmit = {};
  stun_time_ms_t now = 1000;
  stun_time_ms_t wait = 500;

  // seven attempts, the last one 16 s after the sixth
  for (int i = 0; i < 6; ++i) {
    TEST_ASSERT_EQUAL(STUN_RETRANSMIT_DUE,
                      stun_retransmit_poll(&retransmit, now));
    stun_retransmit_advance(&retransmit, now);
    TEST_ASSERT_EQUAL(STUN_RETRANSMIT_WAIT,
                      stun_retransmit_poll(&retransmit, now + wait - 1));
    now += wait;
    wait *= 2;
  }
  TEST_ASSERT_EQUAL(STUN_RETRANSMIT_DUE,
                    stun_retransmit_poll(&retransmit, now));
}

static void test_retransmit_gives_up_8s_after_seventh() {
  stun_retransmit_t retransmit = {};
  stun_time_ms_t now = 0;
  for (int i = 0; i < 7; ++i) {
    now = retransmit.next;
    stun_retransmit_advance(&retransmit, now);
  }

  // as in the RFC's example, 39.5 s after the first
  TEST_ASSERT_EQUAL_UINT64(31500, now);
  TEST_ASSERT_EQUAL_UINT64(39500, retransmit.next);
  TEST_ASSERT_EQUAL(STUN_RETRANSMIT_WAIT,
                    stun_retransmit_poll(&retransmit, 39499));
  TEST_ASSERT_EQUAL(STUN_RETRANSMIT_GAVE_UP,
                    stun_retransmit_poll(&retransmit, 39500));
}

static void test_retransmit_waits_from_actual_send() {
  stun_retransmit_t retransmit = {};
  stun_retransmit_advance(&retransmit, 0);

  // sent late, e.g. after the client was busy, so the next wait starts then
  stun_retransmit_advance(&retransmit, 2000);
  TEST_ASSERT_EQUAL_UINT64(3000, retransmit.next);
}

void retransmit_tests() {
  RUN_TEST(test_retransmit_first_due_right_away);
  RUN_TEST(test_retransmit_doubles_from_500ms);
  RUN_TEST(test_retransmit_gives_up_8s_after_seventh);
  RUN_TEST(test_retransmit_waits_from_actual_send);
}

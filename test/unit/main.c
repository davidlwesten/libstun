#include "runner.h"

void setUp() {}
void tearDown() {}

extern void attribute_tests();
extern void message_tests();
extern void retransmit_tests();
extern void agent_tests();

int main(int argc, char *argv[]) {
  if (!test_runner_init(argc, argv)) {
    return 2;
  }

  UNITY_BEGIN();

  attribute_tests();
  message_tests();
  retransmit_tests();
  agent_tests();

  int const result = UNITY_END();
  return test_runner_selected_test_found() ? result : 2;
}

stun_add_test_executable(unit_tests
  agent.c
  main.c
  message.c
  retransmit.c
  validator.c)

target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/lib)

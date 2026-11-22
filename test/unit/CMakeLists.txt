stun_add_test_executable(unit_tests
  agent.c
  attribute.c
  crc32.c
  main.c
  message.c
  retransmit.c)

target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/lib)

stun_add_test_executable(unit_tests
  main.c
  message.c
  retransmit.c
  session.c)

target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/lib)

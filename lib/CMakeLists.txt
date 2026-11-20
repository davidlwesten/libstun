# The library's sources and settings, shared by the library itself and the copy
# the tests use
function(stun_add_library target)
  add_library(${target} ${ARGN})

  target_compile_features(${target} PUBLIC c_std_23)

  target_sources(${target}
    PRIVATE
      agent.c
      attribute.c
      message.c
      retransmit.c
      stun_wire_gen.c
      validator.c)

  target_include_directories(${target} PUBLIC ${PROJECT_SOURCE_DIR}/include)

  target_link_libraries(${target} PRIVATE stun_warnings)
endfunction()

stun_add_library(stun)

# The tests check the library's own code with ASan and UBSan too, and the
# library that gets used is never sanitized
if(STUN_BUILD_TESTS)
  stun_add_library(stun_sanitized STATIC)
  target_link_libraries(stun_sanitized PUBLIC stun_sanitizers)
endif()

# The wire format is generated from stun.pkt by pktc
# (https://github.com/davidlwesten/pktc). The output is checked in, so pktc is
# only needed to change the schema. When it's installed, editing the schema
# regenerates the code as part of the build, along with pktc's libFuzzer harness
# for it (test/stun_wire_fuzz.c).
find_program(PKTC_EXECUTABLE pktc)
if(PKTC_EXECUTABLE)
  # pktc writes everything into one directory, so generate into the build tree
  # and copy the harness to the tests
  set(PKTC_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/pktc)
  add_custom_command(
    OUTPUT
      ${CMAKE_CURRENT_SOURCE_DIR}/stun_wire_gen.c
      ${CMAKE_CURRENT_SOURCE_DIR}/stun_wire_gen.h
      ${PROJECT_SOURCE_DIR}/test/stun_wire_fuzz.c
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PKTC_OUTPUT}
    COMMAND ${PKTC_EXECUTABLE} --fuzz -o ${PKTC_OUTPUT}
            ${CMAKE_CURRENT_SOURCE_DIR}/stun.pkt
    COMMAND ${CMAKE_COMMAND} -E copy ${PKTC_OUTPUT}/stun_wire_gen.c
            ${PKTC_OUTPUT}/stun_wire_gen.h ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${CMAKE_COMMAND} -E copy ${PKTC_OUTPUT}/stun_wire_fuzz.c
            ${PROJECT_SOURCE_DIR}/test
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/stun.pkt
    COMMENT "Generating the wire format from stun.pkt"
    VERBATIM)
endif()

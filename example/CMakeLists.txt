add_executable(stunc main.c)

target_compile_features(stunc PRIVATE c_std_23)
target_compile_definitions(stunc PRIVATE _POSIX_C_SOURCE=200112L)

target_link_libraries(stunc
  PRIVATE
    stun
    stun_warnings)

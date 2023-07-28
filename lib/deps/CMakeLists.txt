set(BUILD_DOCUMENTATION 0)

unset(CMAKE_C_FLAGS)
unset(CMAKE_C_CLANG_TIDY)
unset(CMAKE_C_INCLUDE_WHAT_YOU_USE)
unset(CMAKE_C_CPPCHECK)

unset(CMAKE_CXX_FLAGS)
unset(CMAKE_CXX_CLANG_TIDY)
unset(CMAKE_CXX_INCLUDE_WHAT_YOU_USE)
unset(CMAKE_CXX_CPPCHECK)

set(CMAKE_POLICY_DEFAULT_CMP0048 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0042 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0054 NEW)

get_directory_property(DEFS COMPILE_DEFINITIONS)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  # list(APPEND DEFS DSTACK)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
  set(IPO False)
endif()
list(APPEND DEFS NDEBUG)

# if (DSTACK AND _finstrument_functions)
#   string(CONCAT CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finstrument-functions")
#   string(CONCAT CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finstrument-functions")
#   list(APPEND DEFS DSTACK)
# endif()

set_directory_properties(PROPERTIES COMPILE_DEFINITIONS "${DEFS}")

add_subdirectory(warpcore EXCLUDE_FROM_ALL)

set(CC_WARNING_FLAGS "-Wno-unused-but-set-variable -Wno-unused-variable")

add_subdirectory(picotls EXCLUDE_FROM_ALL)

set(PTLS_CORE_LIBRARY
  ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-core.a
)

set(PTLS_OPENSSL_LIBRARY
  ${CMAKE_CURRENT_BINARY_DIR}/picotls/libpicotls-openssl.a
)

add_subdirectory(picoquic EXCLUDE_FROM_ALL)

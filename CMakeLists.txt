cmake_minimum_required(VERSION 3.12)

project(quant VERSION 0.0.34 LANGUAGES C CXX)

# See if we have google benchmark
include(CheckCXXSymbolExists)
include(CMakePushCheckState)
include(CheckIncludeFile)
set(CMAKE_REQUIRED_LIBRARIES benchmark)
set(CMAKE_REQUIRED_INCLUDES /usr/local/include)
set(CMAKE_REQUIRED_LINK_OPTIONS -L/usr/local/lib)
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_REQUIRED_LINK_OPTIONS -lc++ ${CMAKE_REQUIRED_LINK_OPTIONS})
endif()
check_cxx_symbol_exists(benchmark::Initialize benchmark/benchmark.h
                        HAVE_BENCHMARK_H)
cmake_reset_check_state()

# See if we have google gperftools
include(CheckSymbolExists)
set(CMAKE_REQUIRED_INCLUDES /usr/local/include)
set(CMAKE_REQUIRED_LIBRARIES profiler)
set(CMAKE_REQUIRED_LINK_OPTIONS -L/usr/local/lib)
check_symbol_exists(ProfilerStart gperftools/profiler.h HAVE_PROFILER)
cmake_reset_check_state()

link_directories(AFTER /usr/local/lib)

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  # on Darwin, try and pick up openssl from homebrew
  set(CMAKE_PREFIX_PATH /usr/local/opt/openssl@1.1 /usr/local/opt/openssl)
endif()

find_package(OpenSSL 1.1.0 REQUIRED)
string(REGEX REPLACE "/include$" "" OPENSSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR})

if("${CMAKE_SYSTEM}" MATCHES "Linux")
  add_compile_definitions(_GNU_SOURCE)
endif()

# Build "Debug" type by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug
        CACHE STRING "Set build type (default Debug)" FORCE)
endif()

# Generate compile_commands.json for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS True)

# Use modern C and C++
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)

# Set general compile flags, if they are supported
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
set (FLAGS -pipe -Wextra -Wpedantic -Weverything -Werror
        -fcolor-diagnostics -fdiagnostics-color=always -fstack-usage
        -Wno-disabled-macro-expansion # clang on travis needs this
        -Wno-missing-field-initializers # and this (clang-5)
        -Wno-extra-semi-stmt # the kh_foreach* macros need this
        -Wno-macro-redefined # because we redefine _FORTIFY_SOURCE
        -Wno-covered-switch-default -Wno-missing-braces
        -Wno-gnu-statement-expression -Wno-reserved-identifier
        -Wno-declaration-after-statement
        -Wno-deprecated-non-prototype
        -fcomment-block-commands=dotfile
        )
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  list(APPEND FLAGS -Wno-poison-system-directories)
endif()
foreach(FLAG ${FLAGS})
  string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
  check_c_compiler_flag(${FLAG} ${F})
  if(${F})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
  endif()
  check_cxx_compiler_flag(${FLAG} ${F})
  if(${F})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAG}")
  endif()
endforeach()

# Set CXX flags
foreach(FLAG -Wno-c++98-compat -Wno-global-constructors)
  string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
  check_cxx_compiler_flag(${FLAG} ${F})
  if(${F})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAG}")
  endif()
endforeach()

# flags for "Debug" and "None" builds
set(CMAKE_C_FLAGS_DEBUG "-g3")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

# disable IPO by default
set(IPO NO)

if(CMAKE_BUILD_TYPE MATCHES Debug)
  if (DSTACK)
    # Check if we can instrument the code
    list(APPEND CMAKE_REQUIRED_FLAGS -finstrument-functions)
    check_c_source_compiles("
      int main() {}
      void __cyg_profile_func_enter(void *this_fn, void *call_site);
      void __cyg_profile_func_enter(void *this_fn __attribute__((unused)),
                                    void *call_site __attribute__((unused))){}
      void __cyg_profile_func_exit(void *this_fn, void *call_site);
      void __cyg_profile_func_exit(void *this_fn __attribute__((unused)),
                                   void *call_site __attribute__((unused))){}
      " _finstrument_functions)
    cmake_reset_check_state()
  endif()

  add_compile_definitions(_FORTIFY_SOURCE=2)

  if(NOT DEFINED ENV{CONTINUOUS_INTEGRATION} AND NOT DOCKER)
    # See if we can use the address sanitizer
    check_include_file(sanitizer/asan_interface.h HAVE_ASAN)
    if(HAVE_ASAN AND NOT CMAKE_GENERATOR STREQUAL Xcode)
      set(CMAKE_REQUIRED_FLAGS -fsanitize=address)
      check_symbol_exists(__asan_address_is_poisoned
                          "sanitizer/asan_interface.h"
                          HAVE_ASAN_ADDRESS_IS_POISONED)
      cmake_reset_check_state()
      set(CMAKE_REQUIRED_FLAGS -fsanitize=address,undefined,leak)
      check_c_compiler_flag("" _fsanitize_address_undefined_leak)
      if(_fsanitize_address_undefined_leak)
        string(CONCAT CMAKE_C_FLAGS "${CMAKE_C_FLAGS} "
                "-fsanitize=address,undefined,leak")
        string(CONCAT CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} "
                "-fsanitize=address,undefined,leak")
      endif()
      unset(CMAKE_REQUIRED_FLAGS)

      # Set some additional flags for Debug builds
      set(FLAGS -Og -fno-omit-frame-pointer -fsanitize-address-use-after-scope
          -fno-optimize-sibling-calls -fno-common
          -fsanitize=unsigned-integer-overflow -fsanitize=local-bounds
          -fsanitize=integer -fsanitize=nullability
          -fsanitize=memory -fsanitize-memory-track-origins
          -fsanitize-memory-use-after-dtor
          -fno-sanitize-recover=all
      )
      foreach(FLAG ${FLAGS})
        string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
        check_c_compiler_flag(${FLAG} ${F})
        if(${F})
          set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAG}")
        endif()
        check_cxx_compiler_flag(${FLAG} ${F})
        if(${F})
          set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FLAG}")
        endif()
      endforeach()
    endif()

    # add -finstrument-functions last, since it interferes with other detection
    if (DSTACK)
      if(_finstrument_functions)
        string(CONCAT CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -finstrument-functions")
        string(CONCAT CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finstrument-functions")
        add_compile_definitions(DSTACK)
      else()
        message(FATAL_ERROR "-finstrument-functions not supported by compiler")
      endif()
    endif()

    find_program(CPPCHECK NAMES cppcheck)
    if(CPPCHECK)
      message(STATUS "Found cppcheck: ${CPPCHECK}")
      set(CMAKE_C_CPPCHECK ${CPPCHECK} -q --inline-suppr
          --enable=all
          --suppress=duplicateValueTernary
          --suppress=missingInclude
          --suppress=missingIncludeSystem
          --suppress=unmatchedSuppression
          --suppress=unusedFunction
          --error-exitcode=2
          -I ${PROJECT_SOURCE_DIR}/lib/include
          -I ${PROJECT_SOURCE_DIR}/lib/deps/warpcore/lib/include
      )
      set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK})
    endif()

    # Use include-what-you-use to check #includes, if it's installed
    find_program(IWYU NAMES include-what-you-use iwyu)
    if(IWYU)
      message(STATUS "Found include-what-you-use: ${IWYU}")
      string(TOLOWER ${CMAKE_SYSTEM_NAME} CMAKE_SYSTEM_NAME_LC)
      set(CMAKE_C_INCLUDE_WHAT_YOU_USE
          ${IWYU} -Xiwyu
          --mapping_file=${PROJECT_SOURCE_DIR}/misc/${CMAKE_SYSTEM_NAME_LC}.imp)
      set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE ${CMAKE_C_INCLUDE_WHAT_YOU_USE})
    endif()

    if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND
        CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      # Use clang-tidy for extra warnings, if it's installed
      find_program(CLANGTIDY NAMES clang-tidy)
      if(CLANGTIDY)
        message(STATUS "Found clang-tidy: ${CLANGTIDY}")
        set(CLANG_TIDY_CHECKS *
            -altera-*
            -bugprone-easily-swappable-parameters
            -bugprone-assignment-in-if-condition,-warnings-as-errors
            -bugprone-implicit-widening-of-multiplication-result
            -bugprone-narrowing-conversions
            -cert-err33-c
            -cert-err58-cpp
            -clang-diagnostic-declaration-after-statement
            -clang-diagnostic-tautological-value-range-compare
            -clang-diagnostic-deprecated-non-prototype
            -concurrency-mt-unsafe
            -cppcoreguidelines-avoid-magic-numbers
            -cppcoreguidelines-avoid-non-const-global-variables
            -cppcoreguidelines-init-variables
            -cppcoreguidelines-macro-usage
            -cppcoreguidelines-narrowing-conversions
            -cppcoreguidelines-owning-memory
            -cppcoreguidelines-pro-bounds-array-to-pointer-decay
            -cppcoreguidelines-pro-bounds-constant-array-index
            -cppcoreguidelines-pro-bounds-pointer-arithmetic
            -cppcoreguidelines-pro-type-vararg
            -fuchsia-default-arguments-calls
            -fuchsia-statically-constructed-objects
            -google-readability-braces-around-statements
            -google-readability-todo
            -google-runtime-references
            -hicpp-braces-around-statements
            -hicpp-multiway-paths-covered
            -hicpp-no-array-decay
            -hicpp-signed-bitwise
            -hicpp-vararg
            -llvmlibc-callee-namespace
            -llvmlibc-implementation-in-namespace
            -llvmlibc-restrict-system-libc-headers
            -modernize-use-trailing-return-type
            -modernize-macro-to-enum
            -performance-no-int-to-ptr
            -readability-braces-around-statements
            -readability-function-cognitive-complexity
            -readability-identifier-length
            -readability-magic-numbers
            -readability-misleading-indentation
            -readability-suspicious-call-argument
        )
        string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS}")
        set(CMAKE_C_CLANG_TIDY ${CLANGTIDY}
            -system-headers -checks=${CLANG_TIDY_CHECKS} --warnings-as-errors=*
        )
        set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY})
      endif()
    endif()
  endif()
else()
  # check for INTERPROCEDURAL_OPTIMIZATION support
  # (except on older gcc where that breaks)
  if(NOT CMAKE_COMPILER_IS_GNUCC
      OR CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 6.0)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IPO)
  else()
    set(IPO False)
  endif()
endif()

if(APPLE AND NOT IPO)
  find_program(DSYMUTIL dsymutil)
endif()


if(FUZZER)
  # check if we have a fuzzer
  set(CMAKE_REQUIRED_FLAGS -fsanitize=fuzzer)
  check_c_compiler_flag(-fsanitize=fuzzer HAVE_FUZZER)
  cmake_reset_check_state()
  if(HAVE_FUZZER)
    add_compile_definitions(FUZZING)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer,address,undefined,leak")
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer,address,undefined,leak")
  else()
    message(WARNING "No fuzzer available")
  endif()
endif()

if(NOT CMAKE_BUILD_TYPE MATCHES Release AND HAVE_PROFILER)
  set(CMAKE_C_STANDARD_LIBRARIES "-lprofiler")
  set(CMAKE_CXX_STANDARD_LIBRARIES ${CMAKE_C_STANDARD_LIBRARIES})
endif()

# flags for "Release" builds
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -Ofast -march=native")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

# flags for "RelWithDebInfo" builds
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -g3")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")

# configuration defines
set (DEFINES
    # FUZZER_CORPUS_COLLECTION
    # MINIMAL_CIPHERS
    # NO_ERR_REASONS
    # NO_MIGRATION
    # NO_OOO_0RTT
    # NO_OOO_DATA
    # NO_QINFO
    # NO_QLOG
    # NO_SERVER
    # NO_SRT_MATCHING
    # NO_TLS_LOG
    # NO_ECN
)

if(NOT WITH_MINICRYPTO)
  list(APPEND DEFINES WITH_OPENSSL)
  if(NOT PTLS_WITH_FUSION_DEFAULT)
      list(APPEND DEFINES PTLS_WITHOUT_FUSION)
  endif()
endif()

if(FUZZER_CORPUS)
  list(APPEND DEFINES FUZZER_CORPUS_COLLECTION)
endif()

add_subdirectory(bin)
add_subdirectory(doc)
add_subdirectory(external EXCLUDE_FROM_ALL)
add_subdirectory(lib)
add_subdirectory(misc)

enable_testing()
add_subdirectory(test)

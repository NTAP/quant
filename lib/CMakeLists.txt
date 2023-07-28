# Get the latest commit hash of the working branch
execute_process(
  # COMMAND git rev-parse HEAD
  # this works in docker:
  COMMAND cat .git/refs/heads/master
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH_STR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX REPLACE "^(..)" "0x\\1, " GIT_COMMIT_HASH "${GIT_COMMIT_HASH_STR}")
string(REGEX REPLACE "^(.*)..$" "\\1" GIT_COMMIT_HASH "${GIT_COMMIT_HASH}")
if(NOT GIT_COMMIT_HASH_STR)
  message(WARNING "Could not determine git commit hash")
  set(GIT_COMMIT_HASH 0x00)
  set(GIT_COMMIT_HASH_STR "00")
endif()

# Get the latest *abbreviated* commit hash of the working branch
execute_process(
  # COMMAND git log -1 --format=%h --abbrev=7
  # this works in docker:
  COMMAND cat .git/refs/heads/master
  COMMAND cut -c 1-7
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH_ABBREV_STR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX REPLACE "^(..)" "0x\\1, " GIT_COMMIT_HASH_ABBREV
       "${GIT_COMMIT_HASH_ABBREV_STR}")
string(REGEX REPLACE "^(.*)..$" "\\1" GIT_COMMIT_HASH_ABBREV
       "${GIT_COMMIT_HASH_ABBREV}")
if(NOT GIT_COMMIT_HASH_ABBREV_STR)
  message(WARNING "Could not determine abbreviated git commit hash")
  set(GIT_COMMIT_HASH_ABBREV 0x00)
  set(GIT_COMMIT_HASH_ABBREV_STR "00")
endif()

string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UC)
configure_file(include/${PROJECT_NAME}/config.h.in
               include/${PROJECT_NAME}/config.h)
configure_file(src/config.c.in src/config.c)

add_subdirectory(deps)

set_property(DIRECTORY . APPEND PROPERTY COMPILE_DEFINITIONS ${DEFINES})

if(HAVE_NETMAP_H)
  set(WARP lib${PROJECT_NAME}-warp)
endif()

include(GNUInstallDirs)

add_library(common
  OBJECT
    src/pkt.c src/frame.c src/quic.c src/stream.c src/conn.c src/pn.c src/qlog.c
    src/diet.c src/util.c src/tls.c src/recovery.c src/marshall.c src/loop.c
    src/cid.c
)

set(TARGETS common lib${PROJECT_NAME} ${WARP})
foreach(TARGET ${TARGETS})
  if(NOT ${TARGET} MATCHES "common")
    add_library(${TARGET}
                $<TARGET_OBJECTS:common>
                ${CMAKE_CURRENT_BINARY_DIR}/src/config.c)

    if(${TARGET} MATCHES ".*-warp")
      target_link_libraries(${TARGET} PUBLIC warpcore)
    else()
      target_link_libraries(${TARGET} PUBLIC sockcore)
    endif()

    if(DSYMUTIL AND BUILD_SHARED_LIBS)
      add_custom_command(TARGET ${TARGET} POST_BUILD
        COMMAND ${DSYMUTIL} ARGS *${CMAKE_STATIC_LIBRARY_SUFFIX}
      )
    endif()

    string(REGEX REPLACE "^lib" "" LIB_NAME ${TARGET})
    set_target_properties(${TARGET}
      PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        OUTPUT_NAME ${LIB_NAME}
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        INTERFACE_POSITION_INDEPENDENT_CODE True
        INTERPROCEDURAL_OPTIMIZATION ${IPO}
    )

    if(NOT WITH_MINICRYPTO)
      set(CRYPTOLIBS picotls-openssl ${OPENSSL_LIBRARIES})
      if (PTLS_WITH_FUSION)
        list(APPENF CRYPTOLIBS picotls-fusion)
      endif()
    else()
      set(CRYPTOLIBS picotls-minicrypto)
    endif()
    target_link_libraries(${TARGET} PRIVATE picotls-core ${CRYPTOLIBS})

    if(${TARGET} MATCHES ".*quant")
      install(DIRECTORY include/${PROJECT_NAME}
              DESTINATION include
              FILES_MATCHING PATTERN "*.h")

      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/${PROJECT_NAME}/config.h
              DESTINATION include/${PROJECT_NAME})
    endif()

    install(TARGETS ${TARGET}
      EXPORT ${TARGET}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
  endif()

  target_include_directories(${TARGET}
    SYSTEM PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
  )

  target_include_directories(${TARGET}
    SYSTEM PRIVATE
      ${OPENSSL_ROOT_DIR}/include
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/deps/timeout>
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/deps/picotls/include>
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/lib/deps/warpcore/lib/include>
      $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/lib/deps/warpcore/lib/include>
  )

endforeach()

cmake_minimum_required(VERSION 3.4)

PROJECT(FELIX)

link_directories($(CMAKE_FIND_ROOT_PATH)/lib64)

find_library (LIBNL_LIBRARY nl-3)
find_library (LIBNL_GENL_LIBRARY nl-genl-3)

set(LIBNL_LIBRARIES ${LIBNL_LIBRARY} ${LIBNL_GENL_LIBRARY})

find_path (LIBNL_INCLUDE_DIR NAMES netlink/netlink.h PATH_SUFFIXES libnl3)

include_directories(include ${LIBNL_INCLUDE_DIR})
add_library(felix_ SHARED lib/common.c lib/acl.c)
set_target_properties(felix_ PROPERTIES OUTPUT_NAME acl)
install(TARGETS felix_ DESTINATION lib)

include_directories(main)
add_executable(acl main/main.c main/arg.c main/acl_cli.c)
target_link_libraries(acl felix_ ${LIBNL_LIBRARIES})
install(TARGETS acl DESTINATION bin)

add_subdirectory(symreg)

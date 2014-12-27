cmake_minimum_required(VERSION 2.8)
project(ykluks)

find_package(PkgConfig)

pkg_search_module(YKPERS REQUIRED ykpers-1>=1.7.0)
pkg_search_module(CRYPTSETUP REQUIRED libcryptsetup>=1.4.0)

include_directories(${YKPERS_INCLUDE_DIRS} ${CRYPTSETUP_INCLUDE_DIRS})

add_executable(ykluks ykluks.c)
target_link_libraries (ykluks ${YKPERS_LIBRARIES} ${CRYPTSETUP_LIBRARIES} -lgcrypt)

if(${BUILD_STATIC})
  message(${BUILD_STATIC})
  pkg_search_module(LIBUSB REQUIRED libusb-1.0)
  add_custom_target(ykluks.static ALL ${CMAKE_C_COMPILER} -static -o ${PROJECT_BINARY_DIR}/ykluks.static ${PROJECT_SOURCE_DIR}/ykluks.c ${YKPERS_STATIC_CFLAGS} ${YKPERS_STATIC_LDFLAGS} ${LIBUSB_STATIC_CFLAGS} ${LIBUSB_STATIC_LDFLAGS} ${CRYPTSETUP_STATIC_CFLAGS} ${CRYPTSETUP_STATIC_LDFLAGS} -lyubikey -luuid -lgcrypt -lgpg-error -ldevmapper -ludev SOURCES ykluks.c)
  
  INSTALL(PROGRAMS ${PROJECT_BINARY_DIR}/ykluks.static DESTINATION sbin)
endif()

INSTALL(TARGETS ykluks
  RUNTIME DESTINATION sbin
)

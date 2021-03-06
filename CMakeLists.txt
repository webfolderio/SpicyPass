cmake_minimum_required(VERSION 3.10)

project(SpicyPass)

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  set(SPICYPASS_INSTALL_DIRECTORY ${CMAKE_INSTALL_PREFIX}/share/spicypass)
  set(GLADE_FILE_PATH ${SPICYPASS_INSTALL_DIRECTORY}/gui.glade)
  set(SpicyPass_LOGO_FILE_PATH ${SPICYPASS_INSTALL_DIRECTORY}/spicypass.svg)
else()
  set(SPICYPASS_INSTALL_DIRECTORY ${CMAKE_INSTALL_PREFIX}/share/spicypass)
  set(GLADE_FILE_PATH "../gui/gui.glade")
  set(SpicyPass_LOGO_FILE_PATH "../icon/spicypass.svg")
endif()

set(SpicyPass_VERSION_MAJOR "0")
set(SpicyPass_VERSION_MINOR "6")
set(SpicyPass_VERSION_PATCH "0")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CLANG_MINIMUM_VERSION 5.0)
set(GCC_MINIMUM_VERSION 7.0)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS GCC_MINIMUM_VERSION)
    message(FATAL_ERROR "Minimum gcc version is ${GCC_MINIMUM_VERSION}")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS CLANG_MINIMUM_VERSION)
    message(FATAL_ERROR "Minimum Clang version is ${CLANG_MINIMUM_VERSION}")
endif()

configure_file(SpicyPassConfig.h.in SpicyPassConfig.h)

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBSODIUM REQUIRED libsodium)
  pkg_check_modules(GTK gtk+-3.0)
endif()

find_package(Threads REQUIRED)

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  if(NOT GTK_FOUND)
      message(WARNING "GTK3 library not found. Compiling without GUI support.")
  else()
      add_definitions(-DGUI_SUPPORT ${GTK_DEFINITIONS})
      set(GUI_INSTALL_FILES gui/gui.glade icon/spicypass.svg)
  endif(NOT GTK_FOUND)
else()
  if(NOT "${GTK_INCLUDE_DIRS}" STREQUAL "")
    add_definitions(-DGUI_SUPPORT)
    set(GUI_INSTALL_FILES gui/gui.glade icon/spicypass.svg)
  endif()
endif()

set(SRC_FILES src/cli.cpp
              src/cli.hpp
              src/crypto.cpp
              src/crypto.hpp
              src/gui.cpp
              src/gui.hpp
              src/load.cpp
              src/load.hpp
              src/password.cpp
              src/password.hpp
              src/spicy.cpp
              src/spicy.hpp
              src/util.cpp
              src/util.hpp
              )

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" AND GTK_FOUND)
  add_executable(spicypass WIN32 ${SRC_FILES})
else()
  add_executable(spicypass ${SRC_FILES})
endif()

target_link_libraries(spicypass Threads::Threads
                                ${LIBSODIUM_LIBRARIES}
                                ${GTK_LIBRARIES}
                                )

target_include_directories(spicypass PUBLIC ${LIBSODIUM_INCLUDE_DIRS}
                                            ${GTK_INCLUDE_DIRS}
                                            )

target_compile_options(spicypass PUBLIC ${LIBSODIUM_CFLAGS_OTHER}
                                        ${GTK_CFLAGS_OTHER}
                                        )

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  if(CMAKE_BUILD_TYPE MATCHES Release)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wno-deprecated -O2 -fstack-protector-all")
  elseif(CMAKE_BUILD_TYPE MATCHES Debug)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Wno-deprecated -O0 -g -fstack-protector-all -DDEBUG")
  else()
      message(FATAL_ERROR "Unsupported build type: ${CMAKE_BUILD_TYPE}")
  endif()
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

target_include_directories(spicypass PUBLIC "${SpicyPass_BINARY_DIR}")

install(TARGETS spicypass DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
install(FILES ${GUI_INSTALL_FILES} DESTINATION ${SPICYPASS_INSTALL_DIRECTORY})
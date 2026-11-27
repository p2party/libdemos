cmake_minimum_required(VERSION 3.28)
project(demos_ledger LANGUAGES C)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
find_package(PkgConfig REQUIRED)
pkg_check_modules(Sodium REQUIRED IMPORTED_TARGET libsodium)

add_library(demos_ledger transfer.c)
target_compile_features(demos_ledger PUBLIC c_std_17)
target_include_directories(demos_ledger PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(demos_ledger PUBLIC OpenSSL::Crypto PRIVATE PkgConfig::Sodium)

include(CTest)
if(BUILD_TESTING)
  add_executable(ledger_transfer_test transfer_test.c)
  target_link_libraries(ledger_transfer_test PRIVATE demos_ledger)
  add_test(NAME ledger_transfer COMMAND ledger_transfer_test)
endif()

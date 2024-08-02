file(GLOB golfdb_sources "*.c*")

add_library(
  golfdb
  STATIC
  ${golfdb_sources}
  )

target_include_directories(
  golfdb
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/phantom-fhe/include
  )

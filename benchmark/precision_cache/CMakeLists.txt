add_executable(precision_cache precision_cache.cu)
target_include_directories(precision_cache PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/phantom-fhe/include ${CMAKE_CURRENT_SOURCE_DIR}/../utils ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(precision_cache golfdb cutfhe++ OpenMP::OpenMP_CXX Phantom)

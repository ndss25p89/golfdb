add_executable(tpch_q6_cache_eviction tpch_q6_cache_eviction.cu)
target_include_directories(tpch_q6_cache_eviction PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/phantom-fhe/include ${CMAKE_CURRENT_SOURCE_DIR}/../utils ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tpch_q6_cache_eviction golfdb cutfhe++ OpenMP::OpenMP_CXX Phantom)

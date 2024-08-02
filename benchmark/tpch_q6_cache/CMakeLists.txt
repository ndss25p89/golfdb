add_executable(tpch_q6_cache tpch_q6_cache.cu)
target_include_directories(tpch_q6_cache PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/phantom-fhe/include ${CMAKE_CURRENT_SOURCE_DIR}/../utils ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tpch_q6_cache golfdb cutfhe++ OpenMP::OpenMP_CXX Phantom)

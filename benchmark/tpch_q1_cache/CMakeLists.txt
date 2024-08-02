add_executable(tpch_q1_cache tpch_q1_cache.cu)
target_include_directories(tpch_q1_cache PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/phantom-fhe/include ../utils)
target_link_libraries(tpch_q1_cache golfdb cutfhe++ OpenMP::OpenMP_CXX Phantom)

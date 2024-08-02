add_executable(tpch_q4_cache tpch_q4_cache.cu)
target_include_directories(tpch_q4_cache PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/phantom-fhe/include ../utils)
target_link_libraries(tpch_q4_cache golfdb cutfhe++ OpenMP::OpenMP_CXX Phantom)

add_executable(comparison_test comparison_test.cpp)
target_link_libraries(comparison_test HEDB)

add_executable(conversion_test conversion_test.cpp)
target_link_libraries(conversion_test HEDB)

add_executable(tpch_q1 tpch_q1.cpp)
target_compile_options(tpch_q1 PRIVATE -DNOCHECK)
target_link_libraries(tpch_q1 HEDB)

add_executable(tpch_q4 tpch_q4.cpp)
target_compile_options(tpch_q4 PRIVATE -DNOCHECK)
target_link_libraries(tpch_q4 HEDB)

add_executable(tpch_q6 tpch_q6.cpp)
target_compile_options(tpch_q6 PRIVATE -DNOCHECK)
target_link_libraries(tpch_q6 HEDB)

add_executable(tpch_q1_c tpch_q1_c.cpp)
target_compile_options(tpch_q1_c PRIVATE)
target_link_libraries(tpch_q1_c HEDB)

add_executable(tpch_q4_c tpch_q4_c.cpp)
target_compile_options(tpch_q4_c PRIVATE -DNOCHECK)
target_link_libraries(tpch_q4_c HEDB)

add_executable(tpch_q6_c tpch_q6_c.cpp)
target_compile_options(tpch_q6_c PRIVATE)
target_link_libraries(tpch_q6_c HEDB)

add_executable(tpch_q6_c_dbe tpch_q6_c_dbe.cpp)
target_compile_options(tpch_q6_c_dbe PRIVATE -DNOCHECK)
target_link_libraries(tpch_q6_c_dbe HEDB)

add_executable(tpch_q6_c_lru tpch_q6_c_lru.cpp)
target_compile_options(tpch_q6_c_lru PRIVATE -DNOCHECK)
target_link_libraries(tpch_q6_c_lru HEDB)

add_executable(tpch_q6_throughput tpch_q6_throughput.cpp)
target_compile_options(tpch_q6_throughput PRIVATE -DNOCHECK)
target_link_libraries(tpch_q6_throughput HEDB)

add_executable(dbe_test dbe_test.cpp)
target_compile_options(dbe_test PRIVATE -DNOCHECK)
target_link_libraries(dbe_test HEDB)

add_executable(comparison_test comparison.cu)
target_link_libraries(comparison_test golfdb cutfhe++ OpenMP::OpenMP_CXX)

add_executable(precision precision.cu)
target_include_directories(precision PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/phantom-fhe/include ${CMAKE_CURRENT_SOURCE_DIR}/../utils ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(precision golfdb cutfhe++ OpenMP::OpenMP_CXX Phantom)

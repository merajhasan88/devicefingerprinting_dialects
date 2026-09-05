cmake_minimum_required(VERSION 3.22.1)
project(codeintegrity)

add_library(codeintegrity SHARED code_integrity.cpp)

find_library(log-lib log)
target_link_libraries(codeintegrity ${log-lib})

cmake_minimum_required(VERSION 3.21)
project(tdcoreclient)
cmake_policy(SET CMP0079 NEW)

add_subdirectory(td EXCLUDE_FROM_ALL)

add_library(tdcoreclient tdcoreclient.cpp)

target_link_libraries(tdcoreclient PRIVATE tdcore)
get_target_property(private_include_dirs tdcore INCLUDE_DIRECTORIES)
get_target_property(private_link_libraries tdcore LINK_LIBRARIES)
target_include_directories(tdcore PRIVATE ${private_include_dirs})
target_link_libraries(tdcore PRIVATE ${private_link_libraries})

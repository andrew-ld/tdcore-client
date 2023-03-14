cmake_minimum_required(VERSION 3.21)
project(tdcoreclient)
cmake_policy(SET CMP0079 NEW)

add_subdirectory(td EXCLUDE_FROM_ALL)

add_library(tdcoreclient tdcoreclient.cpp)
target_include_directories(tdcoreclient PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(tdcoreclient PRIVATE tdcore tdnet tdtl)

get_target_property(private_include_dirs_tdcore tdcore INCLUDE_DIRECTORIES)
get_target_property(private_link_libraries_tdcore tdcore LINK_LIBRARIES)
target_include_directories(tdcore PUBLIC ${private_include_dirs_tdcore})
target_link_libraries(tdcore PRIVATE ${private_link_libraries_tdcore})

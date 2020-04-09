cmake_minimum_required(VERSION 3.5)

project(u5gc_app C)
FILE(GLOB SC_FILES "*.c" "*.h")
add_executable(${PROJECT_NAME} ${SC_FILES})
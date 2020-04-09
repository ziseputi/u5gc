cmake_minimum_required(VERSION 3.5)

project(u5gc_pfcp C)
FILE(GLOB SC_FILES "*.c" "*.h")
add_executable(${PROJECT_NAME} ${SC_FILES})
link_directories("${CMAKE_SOURCE_DIR}/lib" "${LIBGTPNL_DST}/lib" ${LOGGER_DST})
target_include_directories(${PROJECT_NAME} PRIVATE
        ${LOGGER_DST}
        "${CMAKE_SOURCE_DIR}/lib/app"
        )
# CMake 最低版本号要求
cmake_minimum_required(VERSION 3.5)

# 项目名称
project(u5gc-upf)


# 查找指定目录下的所有.cpp与.h文件 并存放到指定变量名SC_FILES中
FILE(GLOB SC_FILES "*.c" "*.h")

# 指定生成目标
add_executable(${PROJECT_NAME} ${SC_FILES} ${APP_FILES})

link_directories("${CMAKE_SOURCE_DIR}/lib" "${LIBGTPNL_DST}/lib" ${LOGGER_DST})
target_include_directories(${PROJECT_NAME} PRIVATE
        ${LOGGER_DST}
        "${CMAKE_SOURCE_DIR}/upf"
        "${CMAKE_SOURCE_DIR}/lib/app"
        "${CMAKE_SOURCE_DIR}/lib/gtp"
        "${CMAKE_SOURCE_DIR}/lib/pfcp"
        )
set_target_properties(
        ${PROJECT_NAME}
        PROPERTIES
        OUTPUT_NAME "${BUILD_BIN_DIR}/u5gc-upf"
        SUFFIX ""
)
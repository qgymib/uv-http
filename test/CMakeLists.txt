cmake_minimum_required(VERSION 3.2)

add_executable(uvhttp_test
    src/cases/file_server.c
    src/cases/simple_server.c
    src/utils/fs.c
    src/main.c)

target_include_directories(uvhttp_test
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

setup_target_wall(uvhttp_test)
target_link_libraries(uvhttp_test PRIVATE uvhttp cutest)

add_test(uvhttp_test uvhttp_test)

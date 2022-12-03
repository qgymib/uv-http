cmake_minimum_required(VERSION 3.2)

add_executable(uvhttp_test
    src/main.c)

setup_target_wall(uvhttp_test)
target_link_libraries(uvhttp_test PRIVATE uvhttp cutest)

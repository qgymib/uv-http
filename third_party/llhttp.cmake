set(LLHTTP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third_party/llhttp)

add_library(llhttp
    ${LLHTTP_ROOT}/src/api.c
    ${LLHTTP_ROOT}/src/http.c
    ${LLHTTP_ROOT}/src/llhttp.c)

target_include_directories(llhttp
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${LLHTTP_ROOT}/include>
    PRIVATE
        ${LLHTTP_ROOT}/src)

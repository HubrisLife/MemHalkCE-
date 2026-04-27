cmake_minimum_required(VERSION 3.16)
project(MemHawkCE VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(MemHawkCE WIN32
    main.cpp
    scanner.cpp
)

target_link_libraries(MemHawkCE PRIVATE
    comctl32 comdlg32 shlwapi shell32 psapi ole32
)

target_compile_definitions(MemHawkCE PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
)

if(MSVC)
    target_compile_options(MemHawkCE PRIVATE /W3 /O2 /MP)
    set_target_properties(MemHawkCE PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
else()
    target_compile_options(MemHawkCE PRIVATE -Wall -O2 -Wno-cast-function-type)
    target_link_options(MemHawkCE PRIVATE -mwindows -static-libgcc -static-libstdc++)
endif()

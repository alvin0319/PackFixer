cmake_minimum_required(VERSION 4.3)
project(PackFixer LANGUAGES C)

# Static CRT so the injected DLL does not depend on whatever runtime DLLs the game ships.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_options(/W3)
add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

# The DLL picks its mode from its own file name, so the output name must contain "bump".
add_library(packfix_bump SHARED src/packfix.c)
target_compile_options(packfix_bump PRIVATE /clang:-mcx16)
target_link_options(packfix_bump PRIVATE /ENTRY:packfix_entry)

add_executable(packfix_test src/packfix_test.c)
add_executable(scan_bench src/scan_bench.c)

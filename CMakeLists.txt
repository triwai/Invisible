cmake_minimum_required(VERSION 3.20)

project(Invisible LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Invisible WIN32 main.cpp)

if (WIN32)
    # Windows標準のAPIのみ - 特にシステム標準ライブラリはOK
    target_link_libraries(Invisible
            setupapi
            cfgmgr32
            advapi32
            user32
            shell32
            gdi32
            comctl32
            ole32
            shlwapi
    )
    target_compile_definitions(Invisible PRIVATE UNICODE _UNICODE)
endif()

# MinGWの場合は静的リンク指定でexe単体で動くように（社外DLL不要）
if (MINGW)
    target_link_options(Invisible PRIVATE
            -municode
            -static
            -static-libstdc++
            -static-libgcc
            -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic
    )
endif()

if (MSVC)
    # ソースが日本語の場合の文字化け防止
    target_compile_options(Invisible PRIVATE /utf-8)
    # MSVCランタイムを静的リンク(/MT)にしてexe単体で完結させる
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
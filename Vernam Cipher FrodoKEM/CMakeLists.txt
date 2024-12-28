cmake_minimum_required(VERSION 3.10)

project("PQUC")

find_package(liboqs CONFIG REQUIRED)

add_executable(pqc main.c)

target_link_libraries(pqc PUBLIC OQS::oqs)
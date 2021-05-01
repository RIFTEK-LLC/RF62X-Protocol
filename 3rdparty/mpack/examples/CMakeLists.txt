cmake_minimum_required(VERSION 3.10.2)


##
## PROJECT
## name and version
##
project(examples LANGUAGES C VERSION 1.1.0)


##
## CONFIGURATION
##
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_C_STANDARD 99)
# Enabling export of all symbols to create a dynamic library
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# create glob files for *.h, *.c
file(GLOB C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
file(GLOB H_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
# concatenate the results (glob files) to variable
set  (SOURCES ${C_FILES} ${H_FILES})


##
## TARGET
## create target and add include path
##
add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} mpack)
target_link_libraries(${PROJECT_NAME} mman)

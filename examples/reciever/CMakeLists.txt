cmake_minimum_required(VERSION 3.13)



###############################################################################
## EXECUTABLE-PROJECT
## name and version
###############################################################################
project(TestReceiver LANGUAGES C)



###############################################################################
## SETTINGS
## basic project settings before use
###############################################################################
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_C_STANDARD 99)
# Enabling export of all symbols to create a dynamic library
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# creating output directory architecture in accordance with GNU guidelines
set(BINARY_DIR "${CMAKE_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${BINARY_DIR}/lib")



###############################################################################
## TARGET
## create target and add include path
###############################################################################
# create glob files for *.h, *.c
file(GLOB C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
file(GLOB H_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
# concatenate the results (glob files) to variable
set  (SOURCES ${C_FILES} ${H_FILES})
# create executable from src
if (NOT TARGET ${PROJECT_NAME})
    add_executable(${PROJECT_NAME} ${SOURCES})
endif()



###############################################################################
## LINK LIBRARIES
## linking all dependencies
###############################################################################
find_package (Threads)
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})

target_link_libraries(${PROJECT_NAME} mpack)
target_link_libraries(${PROJECT_NAME} RF62X-Protocol)

if(MINGW)
    target_link_libraries(${PROJECT_NAME} ws2_32)
    target_link_libraries(${PROJECT_NAME} iphlpapi)
endif(MINGW)

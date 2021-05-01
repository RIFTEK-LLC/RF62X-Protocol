cmake_minimum_required(VERSION 3.10.2)


##
## PROJECT
## name and version
##
project(mman LANGUAGES C VERSION 1.0.0)


##
## CONFIGURATION
##
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_C_STANDARD 99)
# Enabling export of all symbols to create a dynamic library
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

##
## OPTION
##
option (BUILD_SHARED_LIBS "shared/static libs" OFF)
option (BUILD_TESTS "tests?" OFF)

# create glob files for *.h, *.c
file(GLOB C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/sys/*.c)
file(GLOB H_FILES ${CMAKE_CURRENT_SOURCE_DIR}/sys/*.h)
# concatenate the results (glob files) to variable
set  (SOURCES ${C_FILES} ${H_FILES})


##
## TARGET
## create target and add include path
##
add_library(${PROJECT_NAME} ${SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX  "")

if (BUILD_SHARED_LIBS)
        target_compile_definitions(${PROJECT_NAME}
                PUBLIC MMAN_LIBRARY_DLL
                PRIVATE MMAN_LIBRARY
        )
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/)



install (TARGETS ${PROJECT_NAME}
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib${LIB_SUFFIX}
         ARCHIVE DESTINATION lib${LIB_SUFFIX})

install (FILES ${headers} DESTINATION include/sys)

if (BUILD_TESTS)
  enable_testing ()
  add_executable (t_mman sys/test.c)
  target_link_libraries (t_mman ${PROJECT_NAME})
  add_test (NAME t_mman COMMAND t_mman${CMAKE_EXECUTABLE_SUFFIX})
endif ()



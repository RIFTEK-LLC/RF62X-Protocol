cmake_minimum_required(VERSION 3.13)



###############################################################################
## 3RD-PARTY
## dependencies for the project
###############################################################################
project(3rdparty LANGUAGES C)



###############################################################################
## SETTINGS
## basic 3rd-party settings before use
###############################################################################
# To inherit the top-level architecture when the project is used as a submodule.
SET(PARENT ${PARENT}_RF62X_PROTOCOL_)
# Disable self-overwriting of parameters inside included subdirectories.
SET(${PARENT}_SUBMODULE_CACHE_OVERWRITE OFF CACHE BOOL "" FORCE)



###############################################################################
## CONFIGURATION
## 3rd-party submodules configuration
###############################################################################
SET(${PARENT}_MPACK_SUBMODULE                           ON CACHE BOOL "" FORCE)

SET(${PARENT}_RF_PLATFORM_UILS                          ON CACHE BOOL "" FORCE)
if (${PARENT}_RF_PLATFORM_UILS)
    # platform_methods
    SET(${PARENT}_PLATFORM_METHODS                      OFF CACHE BOOL "" FORCE)
    # endian_conv
    SET(${PARENT}_ENDIAN_CONV                           OFF CACHE BOOL "" FORCE)
    # custom_vector
    SET(${PARENT}_CUSTOM_VECTOR                         OFF CACHE BOOL "" FORCE)
    # custom_string
    SET(${PARENT}_CUSTOM_STRING                         OFF CACHE BOOL "" FORCE)
    # pthreads-c
    SET(${PARENT}_PTHREADS4W                            ON CACHE BOOL "" FORCE)
    # getopt
    SET(${PARENT}_GETOPT                                ON CACHE BOOL "" FORCE)
endif()


###############################################################################
## INCLUDING SUBDIRECTORIES
## Adding subdirectories according to the 3rd-party configuration
###############################################################################
if (${PARENT}_MPACK_SUBMODULE)
    add_subdirectory(mpack)
endif()

if (MSVC)
    add_subdirectory(RF-PlatformUtils)
endif()


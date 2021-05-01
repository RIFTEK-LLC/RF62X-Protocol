cmake_minimum_required(VERSION 3.13)



###############################################################################
## PROJECT
## name and version
###############################################################################
project(Examples LANGUAGES C)



###############################################################################
## CONFIGURATION
## project configuration
###############################################################################
SET(${PARENT}_RF62X_PROTOCOL_TEST_RECEIVER             ON CACHE BOOL  "" FORCE)
SET(${PARENT}_RF62X_PROTOCOL_TEST_SENDER               ON CACHE BOOL  "" FORCE)



###############################################################################
## INCLUDING SUBDIRECTORIES
## Adding subdirectories according to the configuration
###############################################################################
if (${PARENT}_RF62X_PROTOCOL_TEST_RECEIVER)
    add_subdirectory(reciever)
endif()
if (${PARENT}_RF62X_PROTOCOL_TEST_SENDER)
    add_subdirectory(sender)
endif()

cmake_minimum_required(VERSION 3.13)



###############################################################################
## PROJECT
## name and version
###############################################################################
project(RF62X-Protocol LANGUAGES C)



###############################################################################
## SETTINGS
## basic project settings before use
###############################################################################
# If this project is used as a submodule, the variable should be overridden
# to "OFF" in the top-level application (to disable forced cache rewriting)
option(${PARENT}_SUBMODULE_CACHE_OVERWRITE "Enable forced cache rewriting" ON)
if (${PARENT}_SUBMODULE_CACHE_OVERWRITE)
    SET(REWRITE_FORCE "FORCE")
else()
    SET(REWRITE_FORCE "")
endif()



###############################################################################
## CONFIGURATION
## project configuration
###############################################################################
# library src
SET(${PARENT}_RF62X_PROTOCOL_LIB            ON CACHE BOOL  "" ${REWRITE_FORCE})

# Examples
SET(${PARENT}_RF62X_PROTOCOL_EXAMPLES       ON CACHE BOOL  "" ${REWRITE_FORCE})



###############################################################################
## INCLUDING SUBDIRECTORIES
## Adding subdirectories according to the configuration
###############################################################################
if (${PARENT}_RF62X_PROTOCOL_LIB)
    # 3rdparty
    add_subdirectory(3rdparty)
    # library src
    add_subdirectory(src)

    # Tests
    if (${PARENT}_RF62X_PROTOCOL_EXAMPLES)
        add_subdirectory(examples)
    endif()
endif()


## our modules are without the "lib" prefix

MACRO(ADD_AND_INSTALL_LIBRARY LIBNAME SRCFILES)
  IF(BUILD_STATIC)
    ADD_LIBRARY(${LIBNAME} STATIC ${SRCFILES})
    TARGET_LINK_LIBRARIES(lighttpd ${LIBNAME})
  ELSE(BUILD_STATIC)
    ADD_LIBRARY(${LIBNAME} SHARED ${SRCFILES})
    SET(L_INSTALL_TARGETS ${L_INSTALL_TARGETS} ${LIBNAME})
    ## Windows likes to link it this way back to app!
    IF(WIN32)
        SET_TARGET_PROPERTIES(${LIBNAME} PROPERTIES LINK_FLAGS lighttpd.lib)
    ENDIF(WIN32)

    IF(APPLE)
        SET_TARGET_PROPERTIES(${LIBNAME} PROPERTIES LINK_FLAGS "-flat_namespace -undefined suppress")
    ENDIF(APPLE)
  ENDIF(BUILD_STATIC)
ENDMACRO(ADD_AND_INSTALL_LIBRARY)

MACRO(LEMON_PARSER SRCFILE)
  GET_FILENAME_COMPONENT(SRCBASE ${SRCFILE} NAME_WE)
  ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${SRCBASE}.c ${CMAKE_CURRENT_BINARY_DIR}/${SRCBASE}.h
  COMMAND ${CMAKE_BINARY_DIR}/build/lemon
  ARGS -q ${CMAKE_CURRENT_SOURCE_DIR}/${SRCFILE} ${CMAKE_SOURCE_DIR}/src/lempar.c
	DEPENDS ${CMAKE_BINARY_DIR}/build/lemon ${CMAKE_CURRENT_SOURCE_DIR}/${SRCFILE}  ${CMAKE_SOURCE_DIR}/src/lempar.c
  COMMENT "Generating ${SRCBASE}.c from ${SRCFILE}"
)
ENDMACRO(LEMON_PARSER)

prglibdir=$(prefix)/bin/samples/rampart/authn_provider
prglib_LTLIBRARIES = libauthn.la
libauthn_la_SOURCES = authn_provider.c
libauthn_la_LIBADD  = 	../../src/core/libmod_rampart.la

INCLUDES = -I ../../include\
			@AXIS2INC@

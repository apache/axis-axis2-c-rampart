TESTS =
prglibdir=$(prefix)/modules/rampart
prglib_LTLIBRARIES = libmod_rampart.la
prglib_DATA= ../data/module.xml

libmod_rampart_la_SOURCES = mod_rampart.c

libmod_rampart_la_LIBADD  = ../handlers/librampart_handlers.la \
			    ../util/librampart_util.la \
			    ../omxmlsec/libomxmlsec.la \
				${AXIS2C_HOME}/lib

INCLUDES = -I$(top_builddir)/include \
			-I$(AXIS2C_HOME)/include/neethi-0.1 \
			-I ../../include \
			@AXIS2INC@

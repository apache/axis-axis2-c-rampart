prglibdir=$(prefix)/services/secconv_echo
samplesdir=$(prefix)/samples/server/secconv_echo
prglib_LTLIBRARIES = libsecconv_echo.la
samples_DATA=echo.c echo_skeleton.c echo.h services.xml Makefile.am Makefile.in
prglib_DATA= services.xml
EXTRA_DIST = services.xml echo.h server_axis2.xml
noinst_HEADERS = echo.h
SUBDIRS =
libsecconv_echo_la_SOURCES = echo.c echo_skeleton.c
libsecconv_echo_la_LIBADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
                    -L$(AXIS2C_HOME)/modules/rampart \
					-lmod_rampart


INCLUDES = @AXIS2INC@ \
	-I$(AXIS2C_HOME)/include \
	            -I ../../../include

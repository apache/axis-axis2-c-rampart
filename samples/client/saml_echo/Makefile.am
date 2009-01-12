prgbindir=$(prefix)/bin/samples/rampart/client/saml_echo
prgbin_PROGRAMS = saml_echo 
datadir=$(prefix)/bin/samples/rampart/client/saml_echo
data_DATA= update_n_run.sh
#samplesdir=$(prefix)/samples/client/echo
#samples_DATA=echo.c README.txt Makefile.am Makefile.in
saml_echo_SOURCES = echo.c 

saml_echo_LDADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
					-L$(AXIS2C_HOME)/modules/rampart \
		    		-lmod_rampart \
					-laxutil \
                    -laxis2_axiom \
					-lneethi \
                    -laxis2_engine \
                    -laxis2_parser \
                    -lpthread \
                    -laxis2_http_sender \
                    -laxis2_http_receiver \
                    $(GUTHTHILA_LIBS) \
                    $(LIBXML2_LIBS)

INCLUDES = @AXIS2INC@ \
		   -I$(AXIS2C_HOME)/include \
            -I ../../../include 

EXTRA_DIST = update_n_run.sh update_n_run.bat

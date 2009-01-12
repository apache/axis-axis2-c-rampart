prgbindir=$(prefix)/bin/samples/rampart/client/saml_protect
prgbin_PROGRAMS = saml_protect
datadir=$(prefix)/bin/samples/rampart/client/saml_protect
data_DATA= update_n_run.sh
saml_protect_SOURCES = echo.c 

saml_protect_LDADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
					-L$(AXIS2C_HOME)/modules/rampart \
					-laxutil \
                    -laxis2_axiom \
					-lneethi \
                    -laxis2_engine \
                    -laxis2_parser \
                    -lpthread \
                    -laxis2_http_sender \
                    -laxis2_http_receiver \
		    		-lmod_rampart \
                    $(GUTHTHILA_LIBS) \
                    $(LIBXML2_LIBS)

INCLUDES = @AXIS2INC@ \
		   -I$(AXIS2C_HOME)/include \
            -I ../../../include 

EXTRA_DIST = update_n_run.sh update_n_run.bat

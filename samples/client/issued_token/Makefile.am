prgbindir=$(prefix)/bin/samples/rampart/client/issued_token
prgbin_PROGRAMS = issued_token 
datadir=$(prefix)/bin/samples/rampart/client/issued_token
#data_DATA= update_n_run.sh
#samplesdir=$(prefix)/samples/client/echo
#samples_DATA=echo.c README.txt Makefile.am Makefile.in
issued_token_SOURCES = echo.c 

issued_token_LDADD   = $(LDFLAGS) \
                    -L$(AXIS2C_HOME)/lib \
					-L$(AXIS2C_HOME)/modules/rampart \
					-laxutil \
                    -laxis2_axiom \
					-lneethi \
					-lsecconv \
                    -laxis2_engine \
                    -laxis2_parser \
                    -lpthread \
                    -laxis2_http_sender \
                    -laxis2_http_receiver \
					-lsaml \
					-ltrust \
					-lmod_rampart \
                    $(GUTHTHILA_LIBS) \
                    $(LIBXML2_LIBS)

INCLUDES = @AXIS2INC@ \
		   -I$(AXIS2C_HOME)/include \
            -I ../../../include 

EXTRA_DIST = update_n_run.sh

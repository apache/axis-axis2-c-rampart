prglibdir=$(prefix)/bin/samples/rampart/replay_detector
prglib_LTLIBRARIES = librdflatfile.la
librdflatfile_la_SOURCES = rampart_replay_detector_flat_file.c
librdflatfile_la_LIBADD  = $(LDFLAGS) \
						   		-L$(AXIS2C_HOME)/lib \
								-laxutil \
								../../src/util/librampart_util.la 
INCLUDES = -I ../../include\
			@AXIS2INC@

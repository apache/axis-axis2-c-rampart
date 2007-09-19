SUBDIRS = src 
docsdir=$(prefix)/docs
includedir=$(prefix)/include/rampart-1.0.0
include_HEADERS=$(top_builddir)/include/*.h
docs_DATA=xdocs/*
EXTRA_DIST = LICENSE NOTICE build.sh autogen.sh samples build test xdocs

check:	
	./rampart-tests.sh



lib_LTLIBRARIES = libtrust.la

libtrust_la_SOURCES = context.c \
					util.c \
					sts_client.c \
					policy_util.c \
					token.c

INCLUDES = -I$(top_builddir)/include \
            -I ../../../../util/include \
            -I ../../../../include \
            -I ../../../../axiom/include \
	    @OPENSSLINC@ \
	    @UTILINC@ \
	    @AXIOMINC@ \
	    @AXIS2INC@

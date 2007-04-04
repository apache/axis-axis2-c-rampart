
AUTOCONF = configure.in
!include $(AUTOCONF)

RAMPART = rampart
RAMPART_SOURCE_DIR = ..\..\

RAMPART_INTDIR = .\int.msvc
RAMPART_DISTDIR = .\..\rampart


#rampart module

OMXMLSEC_SRC = $(RAMPART_SOURCE_DIR)\src\omxmlsec\*.c \
    	       $(RAMPART_SOURCE_DIR)\src\omxmlsec\tokens\*.c \
    	       $(RAMPART_SOURCE_DIR)\src\omxmlsec\c14n\*.c \
    	       $(RAMPART_SOURCE_DIR)\src\omxmlsec\openssl\*.c

SECPOLICY_SRC = $(RAMPART_SOURCE_DIR)\src\secpolicy\builder\*.c \
    	       $(RAMPART_SOURCE_DIR)\src\secpolicy\model\*.c 

MOD_RAMPART_SRC = $(RAMPART_SOURCE_DIR)\src\core\*.c \
		$(RAMPART_SOURCE_DIR)\src\handlers\*.c \
		$(RAMPART_SOURCE_DIR)\src\util\*.c

MOD_RAMPART_INCLUDE_PATH = /I$(RAMPART_SOURCE_DIR)\include \
		           /I$(OPENSSL_BIN_DIR)\include \
			   /I$(AXIS2_BIN_DIR)\include

APPLINK_FILE = $(OPENSSL_BIN_DIR)\include\openssl\applink.c

AXIS2_LIBS = $(AXIS2_BIN_DIR)\lib
AXIS2_MODS = $(AXIS2_BIN_DIR)\modules

##################### compiler options

CC = cl.exe 
CFLAGS = /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "AXIS2_DECLARE_EXPORT"  \
	 /D "AXIS2_SVR_MULTI_THREADED" /w /nologo $(AXIS2_INCLUDE_PATH) 

################### linker options

LD = link.exe
LDFLAGS = /nologo /LIBPATH:$(AXIS2_LIBS) /LIBPATH:$(OPENSSL_BIN_DIR)\lib\VC \
	  /LIBPATH:$(AXIS2_BIN_DIR)\lib


#debug symbols
!if "$(DEBUG)" == "1"
LIBS = $(LIBS) libeay32MTd.lib ssleay32MTd.lib
!else
LIBS = $(LIBS) libeay32MT.lib ssleay32MT.lib
!endif

#################### debug symbol

!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS) /D "_DEBUG" /Od /Z7
LDFLAGS = $(LDFLAGS) /DEBUG /NODEFAULTLIB:LIBCMTD.lib 
!else
CFLAGS = $(CFLAGS) /D "NDEBUG" /O2 /MT
LDFLAGS = $(LDFLAGS)
!endif

#################### hack!
CFLAGS = $(CFLAGS) /D "_WINSOCKAPI_"


distdir:
	if not exist $(RAMPART_DISTDIR) mkdir $(RAMPART_DISTDIR)
	mkdir $(RAMPART_DISTDIR)\bin
	mkdir $(RAMPART_DISTDIR)\bin\clients
	mkdir $(RAMPART_DISTDIR)\bin\services
	mkdir $(RAMPART_DISTDIR)\rampart
	mkdir $(RAMPART_DISTDIR)\samples
	mkdir $(RAMPART_DISTDIR)\include

clean: 
	if exist $(RAMPART_DISTDIR) rmdir /S /Q $(RAMPART_DISTDIR)
	if exist $(RAMPART_INTDIR) rmdir /S /Q $(RAMPART_INTDIR)

intdirs:
	if not exist $(RAMPART_INTDIR) mkdir $(RAMPART_INTDIR)
	mkdir $(RAMPART_INTDIR)\samples\callback\pwcb
	mkdir $(RAMPART_INTDIR)\samples\authn_provider
	mkdir $(RAMPART_INTDIR)\samples\services\echo

mod_rampart:
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(MOD_RAMPART_SRC) $(OMXMLSEC_SRC) $(SECPOLICY_SRC) $(APPLINK_FILE) /Fo$(RAMPART_INTDIR)\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\*.obj \
	      $(LIBS) axutil.lib axiom.lib axis2_parser.lib axis2_engine.lib \
              /DLL /OUT:$(RAMPART_DISTDIR)\rampart\$(RAMPART).dll /IMPLIB:$(RAMPART_DISTDIR)\rampart\mod_rampart.lib
	
	copy $(RAMPART_SOURCE_DIR)\src\data\module.xml $(RAMPART_DISTDIR)\rampart


mod_rampart_pwcb:
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SOURCE_DIR)\samples\callback\pwcb.c /Fo$(RAMPART_INTDIR)\samples\callback\pwcb\ /c
	$(LD) $(LDFLAGS) $(LIBS) axutil.lib $(RAMPART_INTDIR)\samples\callback\pwcb\*.obj /DLL /OUT:$(RAMPART_DISTDIR)\bin\pwcb.dll \
	/IMPLIB:$(RAMPART_DISTDIR)\bin\pwcb.lib


mod_rampart_authn: 
	$(CC) $(CFLAGS) $(MOD_RAMPART_INCLUDE_PATH) $(RAMPART_SOURCE_DIR)\samples\authn_provider\authn_provider.c \
	/Fo$(RAMPART_INTDIR)\samples\authn_provider\ /c
	$(LD) $(LDFLAGS) $(RAMPART_INTDIR)\samples\authn_provider\*.obj mod_rampart.lib axutil.lib /LIBPATH:$(RAMPART_DISTDIR)\rampart /DLL \
	/OUT:$(RAMPART_DISTDIR)\bin\authn.dll /IMPLIB:$(RAMPART_DISTDIR)\bin\authn.lib

mod_rampart_services_sec_echo:
	$(CC) $(CFLAGS) /I$(RAMPART_SOURCE_DIR)\rampart\samples\server\sec_echo \
	$(RAMPART_SOURCE_DIR)\rampart\samples\server\sec_echo\*.c /c
	$(LD) $(LDFLAGS) *.obj $(AXIS2_UTIL).lib $(AXIOM).lib $(AXIS2_PARSER).lib \
	$(LIBS) $(AXIS2_ENGINE).lib $(AXIS2_TRANSPORT_RECEIVER).lib \
	$(AXIS2_TRANSPORT_SENDER).lib /DLL /OUT:sec_echo.dll  
	del *.obj
	
	if not exist $(RAMPART_SAMPLES_SERVICE_DIR)\sec_echo mkdir $(RAMPART_SAMPLES_SERVICE_DIR)\sec_echo

	copy sec_echo.dll $(RAMPART_SAMPLES_SERVICE_DIR)\sec_echo

	del *.dll
	del *.exp
	del *.lib
	
	copy $(RAMPART_SOURCE_DIR)\rampart\samples\server\sec_echo\*.c $(RAMPART_SAMPLES_SERVICE_DIR)\sec_echo
	copy $(RAMPART_SOURCE_DIR)\rampart\samples\server\sec_echo\*.h $(RAMPART_SAMPLES_SERVICE_DIR)\sec_echo
	copy $(RAMPART_SOURCE_DIR)\rampart\samples\server\sec_echo\services.xml $(RAMPART_SAMPLES_SERVICE_DIR)\sec_echo
	
mod_rampart_samples_sec_echo:
	if not exist $(RAMPART_SAMPLES_CLIENT_DIR)\sec_echo mkdir $(RAMPART_SAMPLES_CLIENT_DIR)\sec_echo
	
	$(CC) /nologo /D "WIN32" /D "_WINDOWS" /D "_MBCS" $(AXIS2_INCLUDE_PATH) $(MOD_RAMPART_INCLUDE_PATH) \
	$(RAMPART_SOURCE_DIR)\rampart\samples\client\sec_echo\echo.c /c
	$(LD) $(LDFLAGS) echo.obj $(AXIS2_UTIL).lib $(AXIOM).lib \
	$(AXIS2_PARSER).lib $(AXIS2_ENGINE).lib /OUT:echo.exe

	del *.obj
	copy echo.exe $(RAMPART_SAMPLES_CLIENT_DIR)\sec_echo
	copy $(RAMPART_SOURCE_DIR)\rampart\samples\client\sec_echo\echo.c $(RAMPART_SAMPLES_CLIENT_DIR)\sec_echo
	
	xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\rampart\samples\client\sec_echo\data $(RAMPART_SAMPLES_CLIENT_DIR)\sec_echo\data
	del echo.exe

mod_rampart_samples: mod_rampart_samples_sec_echo mod_rampart_services_sec_echo

mod_rampart_copy_include:
	xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\rampart\include $(AXIS2_BINDIR)\rampart\include
	copy $(RAMPART_SOURCE_DIR)\rampart\README $(AXIS2_BINDIR)\rampart

mod_rampart_copy_keys:
	if not exist $(RAMPART_SAMPLES_KEYS_DIR) mkdir $(RAMPART_SAMPLES_KEYS_DIR)
	xcopy /E /I /Y $(RAMPART_SOURCE_DIR)\rampart\samples\keys\* $(RAMPART_SAMPLES_KEYS_DIR)

mod_rampart_all: mod_rampart mod_rampart_authn mod_rampart_pwcb mod_rampart_htpwcb mod_rampart_samples mod_rampart_copy_include

dist: clean distdir intdirs mod_rampart mod_rampart_pwcb mod_rampart_authn





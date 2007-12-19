TESTS =
datadir=$(prefix)/bin/samples/rampart/secpolicy
SUBDIRS = callback client server keys authn_provider credential_provider data replay_detector
data_DATA=

install-data-hook:
	cp -rf secpolicy/* $(datadir)
	cp -rf README $(datadir)/../
	cp -rf ABOUT_SAMPLES $(datadir)/../

EXTRA_DIST=secpolicy omxmlsec data ABOUT_SAMPLES build.sh



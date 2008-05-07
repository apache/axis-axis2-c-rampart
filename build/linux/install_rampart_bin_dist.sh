#!/bin/bash
echo "Rampart/C binary installer"
R_HOME=$AXIS2C_HOME

echo "Copy modules"
cp -r modules/rampart $R_HOME/modules

echo "Copy libs"
cp lib/* $R_HOME/lib

echo "Copy sample service"
cp -r bin/samples/server/sec_echo $R_HOME/services
cp -r bin/samples/server/secconv_echo $R_HOME/services
cp -r bin/samples/server/saml_sts $R_HOME/services

echo "Copy samples"
rm -rf $R_HOME/bin/samples/rampart
mkdir $R_HOME/bin/samples/rampart
cp -r bin/samples/* $R_HOME/bin/samples/rampart

echo "Copy axis2.xml"
cp bin/samples/server/sec_echo/server_axis2.xml $R_HOME/axis2.xml

cd bin/samples/client/sec_echo/
sh deploy_client_repo.sh

echo "It's done... :)"

echo "Go to bin/samples/secpolicy/ and try a scenario"
echo "   %sh test_scen.sh scenarioX server-port"

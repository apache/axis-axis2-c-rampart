#!/bin/bash
echo "Rampart/C binary dest cleaner"
R_HOME=$AXIS2C_HOME

echo "Remove module"
rm -rf  $R_HOME/modules/rampart

echo "Remove sample service"
rm -rf $R_HOME/services/sec_echo
rm -rf $R_HOME/services/secconv_echo
rm -rf $R_HOME/services/saml_sts

echo "Remove libs"
rm $R_HOME/lib/libomopenssl.*
rm $R_HOME/lib/libomxmlsec.*
rm $R_HOME/lib/liboxstokens.*
rm $R_HOME/lib/libsaml.*
rm $R_HOME/lib/libsecconv.*
rm $R_HOME/lib/libtrust.*
rm $R_HOME/lib/libmod_rampart.*

echo "Remove sample binaries"
rm -rf $R_HOME/bin/samples/rampart

echo "Cleaned... :)"


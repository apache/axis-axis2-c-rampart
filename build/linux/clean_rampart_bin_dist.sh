#!/bin/bash
echo "Rampart/C binary dest cleaner"
R_HOME=$AXIS2C_HOME

echo "Remove module"
rm -rf  $R_HOME/modules/rampart

echo "Remove sample service"
rm -rf $R_HOME/services/sec_echo

echo "Remove libs"
rm $R_HOME/lib/libomopenssl.*
rm $R_HOME/lib/libomxmlsec.*
rm $R_HOME/lib/liboxstokens.*

echo "Remove sample binaries"
rm -rf $R_HOME/bin/samples/rampart

echo "Cleaned... :)"


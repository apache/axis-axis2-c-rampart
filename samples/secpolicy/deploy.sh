#!/bin/bash
if [ $# -ne 1 ]
then
    echo "Usage : $0 scenarioX"
    exit
fi

CLIENT_REPO="$AXIS2C_HOME/client_repo"
SERVICE_HOME="$AXIS2C_HOME/services/sec_echo"

#COPYING THE RELEVENT POLICY FILES TO CLIENT AND SERVER

#copy client policy file to CLIENT_REPO
#echo "Copying client policy files to $CLIENT_REPO"
#cp $1/client-policy.xml $CLIENT_REPO/policy.xml

echo "Replacing settings in policy files."
if [ `uname -s` = Darwin ]
then
    sed -e 's,AXIS2C_HOME,'$AXIS2C_HOME',g' -e 's,\.so,\.dylib,g' $1/client-policy.xml > $CLIENT_REPO/policy.xml
else
    sed 's,AXIS2C_HOME,'$AXIS2C_HOME',g' $1/client-policy.xml > $CLIENT_REPO/policy.xml
fi

#copy services.xml to SERVICE_HOME
#echo "Copying services.xml to $SERVICE_HOME"
#cp $1/services.xml $SERVICE_HOME/services.xml

echo "Replacing settings in Configuration files."
if [ `uname -s` = Darwin ]
then
    sed -e 's,AXIS2C_HOME,'$AXIS2C_HOME',g' -e 's,\.so,\.dylib,g' $1/services.xml > $SERVICE_HOME/services.xml
else
    sed 's,AXIS2C_HOME,'$AXIS2C_HOME',g' $1/services.xml > $SERVICE_HOME/services.xml
fi


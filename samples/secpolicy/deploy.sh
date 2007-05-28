#!/bin/bash
if [ $# -ne 1 ]
then
    echo "Usage : $0 scenarioX"
    exit
fi

CLIENT_REPO="$AXIS2C_HOME/client_repo"
SERVICE_HOME="$AXIS2C_HOME/services/sec_echo/"

#COPYING THE RELEVENT POLICY FILES TO CLIENT AND SERVER

#copy client policy file to CLIENT_REPO
echo "Copying client policy files to $CLIENT_REPO"
cp $1/client-policy.xml $CLIENT_REPO/policy.xml

echo "replacing username in policy files."
sed -i 's,AXIS2C_HOME,'$AXIS2C_HOME',g' $CLIENT_REPO/policy.xml

#copy services.xml to SERVICE_HOME
echo "Copying services.xml to $SERVICE_HOME"
cp $1/services.xml $SERVICE_HOME/services.xml

echo "replacing username in Configuration files."
sed -i 's,AXIS2C_HOME,'$AXIS2C_HOME',g' $SERVICE_HOME/services.xml


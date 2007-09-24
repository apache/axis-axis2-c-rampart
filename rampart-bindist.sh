#!/bin/bash
echo "If you do not need to build Rampart/C %sh rampart-bindist nobuild"
BIN_DIR=rampartc-bin-1.0.0-linux
INCL_V_DIR=rampart-1.0.0
TAR_GZ=$BIN_DIR.tar.gz
MD5=$TAR_GZ.md5
PWDIR=$PWD

if [ $# -ne 1 ]
then
    echo "Build Rampart"
    ./build.sh 

    echo "Build samples"
    cd samples
    ./build.sh
cd ..

fi

echo "Deleting $BIN_DIR, $TAR_GZ, $MD5 if any"
rm -rf $BIN_DIR
rm $TAR_GZ
rm $MD5

ls 
sleep 1

echo "Creating directories in $PWDIR"
mkdir $BIN_DIR
mkdir $BIN_DIR/modules
mkdir $BIN_DIR/modules/rampart
mkdir $BIN_DIR/samples
mkdir $BIN_DIR/samples/secpolicy
mkdir $BIN_DIR/samples/server
mkdir $BIN_DIR/include
mkdir $BIN_DIR/include/$INCL_V_DIR

echo "Copy related files to $BIN_DIR"
#Copy other related files
cp AUTHORS $BIN_DIR
cp COPYING $BIN_DIR
cp INSTALL $BIN_DIR
cp LICENSE $BIN_DIR
cp NEWS $BIN_DIR
cp README $BIN_DIR
cp NOTICE $BIN_DIR

echo "Copy rampart module"
#Copy rampart module
cp -r $AXIS2C_HOME/modules/rampart $BIN_DIR/modules/

echo "Copy samples"
#copy samples
cp -r samples/secpolicy/* $BIN_DIR/samples/secpolicy/
cp -r $AXIS2C_HOME/bin/samples/rampart/* $BIN_DIR/samples/
cp -r $AXIS2C_HOME/services/sec_echo $BIN_DIR/samples/server/
cp samples/server/sec_echo/services.xml $BIN_DIR/samples/server/sec_echo/services.xml
cp samples/server/sec_echo/server_axis2.xml $BIN_DIR/samples/server/sec_echo/server_axis2.xml

echo "Copy headers"
cp include/*.h $BIN_DIR/include/$INCL_V_DIR

echo "Copy docs"
cp -r target/docs $BIN_DIR/

echo "Copy API"
cp -rf xdocs/api $BIN_DIR/docs

echo "Removing garbage in $BIN_DIR"
cd $BIN_DIR

for i in `find . -name "*.svn"`
do
   rm -rf $i
done


cd $PWDIR
echo "Creating tar.gz in $PWDIR"
tar  -czvf $TAR_GZ $BIN_DIR

echo "Creating MD5"
openssl md5 < $TAR_GZ > $MD5

echo "To sign please enter password for the private key"
gpg --armor --output $TAR_GZ.asc --detach-sig $TAR_GZ

echo "Binary DONE" 

#!/bin/bash
BIN_DIR=rampartc-bin-0.90-linux
PWDIR=$PWD

echo "Build Rampart"
#./build.sh 

echo "Build samples"
cd samples
#./build.sh
cd ..


echo "Creating directories in $PWDIR"
mkdir $BIN_DIR
mkdir $BIN_DIR/modules
mkdir $BIN_DIR/samples

echo "Copy related files to $BIN_DIR"
#Copy other related files
cp AUTHORS $BIN_DIR
cp COPYING $BIN_DIR
cp INSTALL $BIN_DIR
cp LICENSE $BIN_DIR
cp NEWS $BIN_DIR
cp README $BIN_DIR

echo "Copy rampart module"
#Copy rampart module
cp $AXIS2C_HOME/modules/rampart/libmod_rampart.so $BIN_DIR/modules
cp $AXIS2C_HOME/modules/rampart/module.xml $BIN_DIR/modules

echo "Copy samples"
#copy samples
cp -r samples/secpolicy/* $BIN_DIR/samples

echo "Removing garbage"
cd $BIN_DIR
for i in `find . -name "*.la"`
do
   rm $i
done

for i in `find . -name "*.svn"`
do
   rm -rf $i
done

cd $PWDIR
echo "Creating tar.gz in $PWDIR"
tar  -czvf $BIN_DIR.tar.gz $BIN_DIR

echo "Create MD5"
openssl md5 < $BIN_DIR.tar.gz > $BIN_DIR.tar.gz.md5

echo "Sign"
gpg --armor --output $BIN_DIR.tar.gz.asc --detach-sig $BIN_DIR.tar.gz
echo "DONE"

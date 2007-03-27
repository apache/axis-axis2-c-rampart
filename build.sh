#!/bin/bash
./autogen.sh
./configure --prefix=${AXIS2C_HOME} --enable-static=no --with-axis2=${AXIS2C_HOME}/include
make
make install

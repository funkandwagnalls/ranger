#!/bin/bash
:<<'COMMENT'
Author: Chris Duffy
Date: 2015
Name: setup.sh
Purpose: This installation file does the basic installation of PIP, and relevant Python libraries.
Systems: This has only been tested on Kali
Copyright (c) 2015, Christopher Duffy All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: * Redistributions
of source code must retain the above copyright notice, this list of conditions and
the following disclaimer. * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution. * Neither the
name of the nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
COMMENT

# Installing PIP
#apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y # Uncomment if necessary
apt-get -y install python-setuptools python-dev python-pip

# Install Python libraries
pip install netifaces python-nmap scapy msgpack-python twill xlsxwriter
# Upgrade requests
pip install request --upgrade

# Clone MSFRPC
cd /opt
git clone https://github.com/SpiderLabs/msfrpc.git

# Install Perl interface for MSFRPC
cd /opt/msfrpc/Net-MSFRPC
perl Makefile.PL
make
make install

# Install Python interface for MSFRPC
cd /opt/msfrpc/python-msfrpc
python ./setup.py build
python ./setup.py install

cd ~
wget https://pypi.python.org/packages/source/i/impacket/impacket-0.9.13.tar.gz
tar -xzvf impacket-0.9.13.tar.gz && mv impacket-0.9.13 impacket
cd impacket && python setup.py install
rm ~/impacket-0.9.13.tar.gz
cd examples && wget https://raw.githubusercontent.com/funkandwagnalls/ranger/testing/ranger.py && chmod a+x ranger.py

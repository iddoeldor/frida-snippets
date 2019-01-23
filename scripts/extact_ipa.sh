#!/bin/bash
# Extracting IPA from Jailbroken +Frida device
# The IPA will be @ /tmp/ios_ssh/iphonessh/python-client/frida-ios-dump/AppName.ipa
mkdir /tmp/ios_ssh
cd "$_"
sudo apt-get install libgcrypt20-doc gnutls-doc gnutls-bin usbmuxd libimobiledevice*
git clone https://github.com/rcg4u/iphonessh
cd iphonessh/python-client/
chmod +x *
python2.7 tcprelay.py -t 22:2222 &
TCP_RELAY_PID=$!
git clone https://github.com/AloneMonkey/frida-ios-dump.git
cd frida-ios-dump
git checkout origin/3.x
sudo -H pip3 install -r requirements.txt --upgrade
sudo python3.6 dump.py $1  # com.app.bundle.id
kill $TCP_RELAY_PID

#!/usr/bin/env bash
# Download latest frida-server, extract, push & run on android device/emulator
# adb 1.0.32, jq 1.5, xz 5.1, wget 1.17.1
# sudo apt install wget jq xz

# PARCH = phone architecture 
# if oneliner [[ == "armeabi-v7a" ]] is a dirty fix because frida's release for armeabi-v7a is just "arm"

# TODO fix adb root which does not work on phones, only emulators, use `adb shell su` instead

PARCH=`adb shell getprop ro.product.cpu.abi`;\
[[ "${PARCH}" == "armeabi-v7a" ]] && PARCH="arm";\
wget -q -O - https://api.github.com/repos/frida/frida/releases \
| jq '.[0] | .assets[] | select(.browser_download_url | match("server(.*?)android-'${PARCH}'*\\.xz")).browser_download_url' \
| xargs wget -q --show-progress $1 \
&& unxz frida-server* \
&& adb root \
&& adb push frida-server* /data/local/tmp/frida-server \
&& adb shell "chmod 755 /data/local/tmp/frida-server" \
&& adb shell "/data/local/tmp/frida-server &"

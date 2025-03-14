#!/bin/bash

# set -x

function stripleadingzeros()
{
    if [[ "$1" != "" ]]
    then
        echo $((10#$1))
    fi
}

: ${DISKFILE:=$HOME/vms/ubuntu.ext4}

# Pick up a yubikey if one is there
yubistr=""
HBUS=$(stripleadingzeros `lsusb | grep Yubico | awk '{print $2}'`)
HADDR=$(stripleadingzeros `lsusb | grep Yubico | awk '{print $4}' | sed -e 's/://'`)
if [[ "$HBUS" != "" && "$HADDR" != "" ]]
then
    yubistr=" -usb -device usb-host,hostbus=$HBUS,hostaddr=$HADDR "
fi

# Pick up a solokey if one is there (see https://solokeys.eu/)
solostr=""
HBUS=$(stripleadingzeros `lsusb | grep "Solo 2" | awk '{print $2}'`)
HADDR=$(stripleadingzeros `lsusb | grep "Solo 2" | awk '{print $4}' | sed -e 's/://'`)
if [[ "$HBUS" != "" && "$HADDR" != "" ]]
then
    solostr=" -usb -device usb-host,hostbus=$HBUS,hostaddr=$HADDR "
fi

# start the guest
debvm-run -g -s 2222 -i $DISKFILE -- -m 16G $yubistr $solostr \
    -vga none -device virtio-vga-gl -display sdl,gl=on

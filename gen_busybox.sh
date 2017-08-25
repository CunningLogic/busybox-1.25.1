#
# https://releases.linaro.org/components/toolchain/binaries/5.1-2015.08/armeb-linux-gnueabi/
#
export PATH=~/gcc/gcc-linaro-5.1-2015.08-x86_64_arm-linux-gnueabi/bin:$PATH

CROSS_COMPILE=arm-linux-gnueabi-
#CROSS_COMPILE=arm-linux-gnueabihf-

make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE defconfig
#make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE menuconfig
# busybox settings: [*] Build BusyBox as a static binary (no shared libs)
# network utilities: ftpd: [ ] Enable authentication

#make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE -j32 clean
make ARCH=arm CROSS_COMPILE=$CROSS_COMPILE -j32

cp -rf busybox ../../../device/leadcore/common/busybox

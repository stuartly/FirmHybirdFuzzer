sudo apt-get build-dep -y qemu

mkdir ../build-qemu && cd ../build-qemu

../avatar-qemu/configure --python=python3 --target-list="arm-softmmu" --disable-vnc --disable-curses --disable-sdl --disable-hax --disable-rdma --enable-debug --enable-pie --enable-kvm --enable-linux-user --disable-gtk


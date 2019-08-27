

mkdir ../build && cd ../build

../avatar-panda/configure --disable-sdl --target-list=arm-softmmu --extra-cflags="-I/path/to/capstone/include" --extra-ldflags='-L/path/to/capstone/library.so'

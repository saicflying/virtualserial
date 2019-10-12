rm -rf bin/*
mkdir -p bin/x86/
mkdir -p bin/arm/
make clean
make 
make install
make clean
EMBD=arm make 
EMBD=arm make install

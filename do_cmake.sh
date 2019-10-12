#!/bin/sh -x
if test ! -e build; then
	mkdir build
fi

cd build
cmake "$@" ..

echo done

#!/bin/bash

# rm -rf build/

meson setup ../build --reconfigure

ninja -C ../build
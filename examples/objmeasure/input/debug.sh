#!/bin/bash

gdb -ex "target remote localhost:1234" -ex "source ./snap.py" -ex "c"

#!/bin/bash

target=$1
for file in $*
do
    if [ $target != $file ]; then
        if [ -f $file ]; then
            mv $file $target    
        fi
    fi
done

#!/bin/bash

grep "\-ccc\->" laelaps.txt > yy
grep "1\-ccc\->" yy | wc -l
grep "2\-ccc\->" yy | wc -l
grep "3\-ccc\->" yy | wc -l
grep "4\-ccc\->" yy | wc -l
rm yy

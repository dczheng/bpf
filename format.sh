#!/bin/sh

FILES=$(find . -name "*.[c|h]")

sed -n '/ \+$/p' ${FILES}
sed -n '/( \+\(\S\)/p' ${FILES}
sed -n '/\(\S\) \+)/p' ${FILES}
sed -n '/\t/p' ${FILES}

sed -i 's/ \+$//g' ${FILES}
sed -i 's/( \+\(\S\)/(\1/g' ${FILES}
sed -i 's/\(\S\) \+)/\1)/g' ${FILES}
sed -i 's/\t/    /g' ${FILES}

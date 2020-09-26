#!/bin/bash

for curr_file in `find ./opt -name \*.labeled`
do
    echo "processing, ${curr_file}"

    # for cut command, TAB is the default field delimiter char
    cut -f 21 ${curr_file} > /tmp/cut.output
    n_rows=`cat /tmp/cut.output | wc -l`
    echo "total rows, ${n_rows}"

    while read -r curr_label
    do
        n_label_occurrences=`grep -e "${curr_label}" /tmp/cut.output | wc -l`
        echo "${curr_label},${n_label_occurrences}"
    done < <(sort -u /tmp/cut.output | grep -v ^$)
done

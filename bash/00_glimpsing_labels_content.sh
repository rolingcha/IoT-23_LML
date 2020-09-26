#!/bin/bash

function f_list_labels () {
	for curr_filename in `find ./ -name \*.labeled`
	do
		wc -l ${curr_filename} 
		cut -f21 ${curr_filename} > f_list_labels_col21 
		sort -u f_list_labels_col21
	done
}


function f_show_n_samples_by_file () {
	for curr_filename in `find ./ -name \*.labeled`
	do
		wc -l ${curr_filename}
	done
}

#f_show_n_samples_by_file
f_list_labels

# -*- coding: utf-8 -*-
"""
Created on Fri Jun 12 10:51:28 2020

@author: Rolando Inglés
"""

import re
import iot_23_utils as iotutils

RETURN_NOT_OK=-1
RETURN_OK=0


global_tags_list = ('5K', '10K', '25K', '50K', '100K')

global_input_files_dict = {
    '00': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-Honeypot-Capture-4-1\bro\conn.log.labeled',
    '01': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-Honeypot-Capture-5-1\bro\conn.log.labeled', 
    '02': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-Honeypot-Capture-7-1\Somfy-01\bro\conn.log.labeled', 
    '03': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-1-1\bro\conn.log.labeled', 
    '04': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-17-1\bro\conn.log.labeled', 
    '05': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-20-1\bro\conn.log.labeled', 
    '06': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-21-1\bro\conn.log.labeled', 
    '07': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-3-1\bro\conn.log.labeled', 
    '08': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-33-1\bro\conn.log.labeled', 
    '09': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-34-1\bro\conn.log.labeled', 
    '10': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-35-1\bro\conn.log.labeled', 
    '11': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-36-1\bro\conn.log.labeled', 
    '12': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-39-1\bro\conn.log.labeled', 
    '13': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-42-1\bro\conn.log.labeled', 
    '14': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-43-1\bro\conn.log.labeled', 
    '15': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-44-1\bro\conn.log.labeled', 
    '16': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-48-1\bro\conn.log.labeled', 
    '17': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-49-1\bro\conn.log.labeled', 
    '18': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-52-1\bro\conn.log.labeled', 
    '19': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-60-1\bro\conn.log.labeled', 
    '20': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-7-1\bro\conn.log.labeled', 
    '21': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-8-1\bro\conn.log.labeled', 
    '22': r'.\opt\Malware-Project\BigDataset\IoTScenarios\CTU-IoT-Malware-Capture-9-1\bro\conn.log.labeled', 
}

global_labels_dict = {'00': {'-   benign   -': {'5K': 22, '10K': 45, '25K': 113, '50K': 226, '100K': 406}}, 
 '01': {'-   benign   -': {'5K': 68, '10K': 137, '25K': 343, '50K': 687, '100K': 1236}}, 
 '02': {'-   benign   -': {'5K': 6, '10K': 13, '25K': 32, '50K': 65, '100K': 117}}, 
 '03': {'Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   C&C': {'5K': 1, '10K': 2, '25K': 3, '50K': 4, '100K': 7}}, 
 '04': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   Okiru': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   DDoS': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-HeartBeat': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   Attack': {'5K': 1, '10K': 2, '25K': 3, '50K': 3, '100K': 3}, 
        '-   Malicious   PartOfAHorizontalPortScan-Attack': {'5K': 1, '10K': 2, '25K': 3, '50K': 4, '100K': 4}}, 
 '05': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-Torii': {'5K': 1, '10K': 2, '25K': 4, '50K': 8, '100K': 14}}, 
 '06': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-Torii': {'5K': 1, '10K': 2, '25K': 3, '50K': 7, '100K': 12}},
 '07': {'Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   C&C': {'5K': 1, '10K': 2, '25K': 3, '50K': 4, '100K': 7}, 
        'Malicious   Attack': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '08': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   Okiru': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-HeartBeat': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '09': {'-   Benign   -': {'5K': 96, '10K': 192, '25K': 480, '50K': 961, '100K': 1730}, 
        '-   Malicious   C&C': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 6, '10K': 12, '25K': 30, '50K': 61, '100K': 109}, 
        '-   Malicious   DDoS': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '10': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C': {'5K': 4, '10K': 8, '25K': 20, '50K': 40, '100K': 72}, 
        '-   Malicious   C&C-FileDownload': {'5K': 1, '10K': 2, '25K': 3, '50K': 6, '100K': 10}, 
        '-   Malicious   Attack': {'5K': 1, '10K': 1, '25K': 1, '50K': 2, '100K': 2}, 
        '-   Malicious   DDoS': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '11': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-HeartBeat': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   Okiru': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   Okiru-Attack': {'5K': 1, '10K': 1, '25K': 2, '50K': 2, '100K': 3}}, 
 '12': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C': {'5K': 76, '10K': 153, '25K': 382, '50K': 765, '100K': 1377}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   Attack': {'5K': 33, '10K': 67, '25K': 169, '50K': 338, '100K': 609}}, 
 '13': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   FileDownload': {'5K': 1, '10K': 1, '25K': 2, '50K': 2, '100K': 3}, 
        '-   Malicious   C&C-FileDownload': {'5K': 1, '10K': 1, '25K': 2, '50K': 2, '100K': 3}}, 
 '14': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-FileDownload': {'5K': 1, '10K': 2, '25K': 4, '50K': 7, '100K': 13}, 
        '-   Malicious   Okiru': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   FileDownload': {'5K': 1, '10K': 1, '25K': 1, '50K': 1, '100K': 1}, 
        '-   Malicious   DDoS': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '15': {'-   Benign   -': {'5K': 10, '10K': 21, '25K': 52, '50K': 105, '100K': 189}, 
        '-   Malicious   C&C-FileDownload': {'5K': 1, '10K': 2, '25K': 3, '50K': 5, '100K': 9}, 
        '-   Malicious   C&C': {'5K': 1, '10K': 2, '25K': 4, '50K': 7, '100K': 12}, 
        '-   Malicious   DDoS': {'5K': 1, '10K': 1, '25K': 1, '50K': 1, '100K': 1}}, 
 '16': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-HeartBeat-FileDownload': {'5K': 1, '10K': 2, '25K': 3, '50K': 5, '100K': 9}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   Attack': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-HeartBeat-Attack': {'5K': 41, '10K': 83, '25K': 208, '50K': 417, '100K': 750}, 
        '-   Malicious   C&C-PartOfAHorizontalPortScan': {'5K': 44, '10K': 88, '25K': 222, '50K': 444, '100K': 799}}, 
 '17': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   FileDownload': {'5K': 1, '10K': 2, '25K': 4, '50K': 7, '100K': 12}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C': {'5K': 96, '10K': 192, '25K': 480, '50K': 961, '100K': 1729}, 
        '-   Malicious   C&C-FileDownload': {'5K': 1, '10K': 1, '25K': 1, '50K': 1, '100K': 1}}, 
 '18': {'-   Benign   -': {'5K': 89, '10K': 179, '25K': 448, '50K': 897, '100K': 1614}, 
        '-   Malicious   C&C-FileDownload': {'5K': 1, '10K': 2, '25K': 3, '50K': 6, '100K': 10}, 
        '-   Malicious   C&C': {'5K': 1, '10K': 2, '25K': 2, '50K': 3, '100K': 5}, 
        '-   Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-Mirai': {'5K': 1, '10K': 1, '25K': 1, '50K': 2, '100K': 2}}, 
 '19': {'-   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        '-   Malicious   C&C-HeartBeat': {'5K': 4, '10K': 9, '25K': 23, '50K': 47, '100K': 85}, 
        '-   Malicious   DDoS': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '20': {'Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   C&C-HeartBeat': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   Okiru': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   DDoS': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'COLnd035cNITygYHp3   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'CARhxZ3hLNVO3xYFok   Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '21': {'Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 1962}, 
        'Malicious   C&C': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}, 
 '22': {'Benign   -': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}, 
        'Malicious   PartOfAHorizontalPortScan': {'5K': 100, '10K': 200, '25K': 500, '50K': 1000, '100K': 2000}}
}   

##
# @name clean_output_files
#
# Objective: cleaning up all the file previously generated
#
# params: None
#
def clean_output_files():
    # to be done
    print("to be done")


##
# @name get_rows_by_label_into_output_file
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def cp_lines_by_label(output_filename="output.csv",
                      input_filename='input.csv', 
                      label_to_get='nolabel',
                      n_lines_to_cp=0):
    print('copying %d %s\'s lines into %s' % 
          (n_lines_to_cp, label_to_get, output_filename))

    line_cnt = 0
                # e.g. ,Benign$
    
    reg_expr = label_to_get.replace(' ', r'\s')+'$'
    #reg_expr = reg_expr.replace(' ', r'\s')
 
    # could be needed os.path.join
    # python 3 from pathlib import Path
    
    with open(output_filename, 'a') as csv_output_file:
        with open(input_filename) as csv_input_file:
            for input_line in csv_input_file:
                if re.search(reg_expr, input_line):
                    csv_output_file.write(input_line.replace('\t', ','))
                    line_cnt += 1
                    if line_cnt == n_lines_to_cp:
                        return line_cnt

    return line_cnt

##
# @name generate_train_test_sets
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def copy_header_into_output_csv(output_filename="nofilename"):
    # taking the features names (HEADER) from the very first
    # input file declared in the processing dictionary
    
    if not '00' in global_input_files_dict:
        print('key 00 not found on input file dictionary')
        return RETURN_NOT_OK
    
    tsv_input_filename = global_input_files_dict['00']
    
    with open(output_filename, 'w') as tsv_output_file:
        with open(tsv_input_filename, 'r') as tsv_input_file:
            # getting the proper line where the features names are
            for skipping_header_row in range (0,6):
                tsv_input_file.readline()
            features_names = tsv_input_file.readline().split('\t')
            features_names = ','.join(features_names[1:])
            tsv_output_file.write(features_names)

    return RETURN_OK
    
##
# @name generate_train_test_sets
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def generate_train_test_sets(output_file_tag="notag"):
    
    task_output_filename = iotutils.get_iot_23_output_filename(output_file_tag)
    
    # creating or truncating file by copying the features header
    if copy_header_into_output_csv(task_output_filename) == RETURN_NOT_OK:
        return RETURN_NOT_OK
    
    for file_key, file_val in global_input_files_dict.items():
        task_input_tsv_filename = file_val
        
        if not file_key in global_labels_dict:
            continue
        
        processing_labels_dict = global_labels_dict[file_key]
        
        for label_key, label_val in processing_labels_dict.items():
            processing_tags_dict = label_val
            
            if not output_file_tag in processing_tags_dict:
                continue
            
            n_lines_to_cp = processing_tags_dict[output_file_tag]

            n_sent_lines =  cp_lines_by_label(task_output_filename,
                                               task_input_tsv_filename,
                                               label_key,
                                               n_lines_to_cp)
            
            if n_sent_lines == n_lines_to_cp:
                print('OK')
            else:
                print('ERROR: %d != %d, file_key=%s, label_key=%s, label_val=%s'
                      % (n_sent_lines, n_lines_to_cp, file_key, label_key, label_val))
                return RETURN_NOT_OK
    return RETURN_OK            

##
# @name clean_output_files
#
# Objective: cleaning up all the file previously generated
#
# Parameters: None
#
# Returns:
#
def main():
    for output_file_tag in global_tags_list:
        if RETURN_OK == generate_train_test_sets(output_file_tag):
            print('done!')
                
if __name__ == "__main__":
    main()


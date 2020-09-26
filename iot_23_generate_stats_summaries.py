# -*- coding: utf-8 -*-
"""
Created on Thu Jul 30 20:15:50 2020

@author: Rolando Inglés
"""
import os
import pandas as pd

stats_dirs_root_dir = './'
model_name_prefix = 'ohl'

def do_csv_files_summary(root_work_dir=None, stats_work_dir=None):
    nhl_tag_list = ['input',
                    'output',
                    'twice_input',
                    'twice_output',
                    'two_thirds_inputs_plus_outputs',
                    'less_than_twice_input']
    split_ratios_list = ['15', '20', '25']
    features_kind_list = ['both', 'categorical', 'scalar']
    dataset_labels_list = ['5K', '10K', '25K', '50K', '100K']
  
    for curr_nhl_tag in nhl_tag_list:            
        for curr_ratio in split_ratios_list:
            for curr_features_kind in features_kind_list:
                X_series_are_set = False
                summary_df = pd.DataFrame()
                summary_filename = '{}_k_cols_{}_s_ratio_{}_nhln_{}_summary.csv'.format(model_name_prefix, curr_features_kind, curr_ratio, curr_nhl_tag)
                for curr_dataset_label in dataset_labels_list:
                    stats_filename = '{}_ds_{}_k_cols_{}_s_ratio_{}_nhln_{}.csv'.format(model_name_prefix, curr_dataset_label, curr_features_kind, curr_ratio, curr_nhl_tag)
            
                    stats_path_filename = '{}/{}/{}'.format(root_work_dir, stats_work_dir, stats_filename)
                    if os.path.isfile(stats_path_filename):
                        stats_df = pd.read_csv(stats_path_filename)
                        
                        if not X_series_are_set:
                            X_series_are_set = True
                            summary_df['batch_size'] = stats_df['batch_size']
                            summary_df['epochs'] = stats_df['epochs']
                        summary_df[curr_dataset_label] = stats_df['accuracy']
                if not summary_df.empty:
                    summary_df.to_csv('{}/{}/{}'.format(root_work_dir, stats_work_dir, summary_filename))
        
        
if __name__ == '__main__':
    with os.scandir(stats_dirs_root_dir) as it:
        for entry in it:
            if entry.name.startswith('stats') and entry.is_dir():
                print('summarizing {}'.format(entry.name))
                do_csv_files_summary(root_work_dir=stats_dirs_root_dir, 
                                     stats_work_dir=entry.name)
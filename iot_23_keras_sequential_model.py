# -*- coding: utf-8 -*-
"""
Created on Sat Jul 18 17:59:37 2020

@author: Rolando Inglés
"""
# %% imports

# python imports
import os
import sys
import getopt
import time
import datetime

# data wrangling imports
import numpy as np
import pandas as pd

# scikit's
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# keras's imports
from keras.utils import np_utils
from keras.models import Sequential
from keras.layers import Input
from keras.layers import Dense
from keras.callbacks import EarlyStopping

# plotting imports
import matplotlib.pyplot as plt

# IoT-23 specific imports
import iot_23_data_set_wrangling as iot_wrangling

# %% constants
RETURN_OK = 0
RETURN_NOT_OK = -1
RETURN_USAGE = -2

exec_params = {'data-set-tag': '0K', 
               'split-ratio': 0,
               'kind-of-columns': '',
               'num-hl-nodes': ''}

def print_usage(argv):
    print('{} <-t|--data-set-tag=> <-r|--split-ratio=> <-c|--kind-of-columns=> <-n|--num-hl-nodes=>'.format(argv[0]))
    print('where:')
    print('-t <5K|10K|25K|50K|100K>')
    print('-r <15|20|25>')
    print('-c <both|categorical|scalar>')
    print('-n <input|output|twice_input|twice_output|two_thirds_inputs_plus_outputs|less_than_twice_input>')

    
def parsing_argv(argv):
    try:
        opts, args = getopt.getopt(argv[1:], 'ht:r:k:c:', 
                                   ['data-set-tag=','split-ratio=', 'kind-of-columns=', 'num-hl-nodes='])
    except getopt.GetoptError:
        print_usage(argv)
        return RETURN_NOT_OK
        
    for opt, arg in opts:
        if opt == '-h':
            print_usage(argv)
            return RETURN_USAGE
        elif opt in ('-t', '--data-set-tag'):
            if arg in ('5K', '10K', '25K', '50K', '100K'):
                exec_params['data-set-tag'] = arg.strip()
        elif opt in ('-r', '--split-ratio'):
            exec_params['split-ratio'] = int(arg)/100      
        elif opt in ('-c', '--kind-of-columns'):
            if arg in ('scalar', 'categorical', 'both'):
                exec_params['kind-of-columns'] = arg.strip()
        elif opt in ('-n', '--num-hl-nodes'):
            if arg in ('input', 'output',
                       'twice_input', 'twice_output',
                       'two_thirds_inputs_plus_outputs', 'less_than_twice_input'):
                exec_params['num-hl-nodes'] = arg.strip()

    if ('0K' == exec_params['data-set-tag'] 
    or 0 == exec_params['split-ratio']
    or '' == exec_params['kind-of-columns']
    or '' == exec_params['num-hl-nodes']):
        print_usage(argv)
        return RETURN_NOT_OK
    else:
        return RETURN_OK
    
def load_data_set(data_set_tag="0K"):
    """Loads the data from the IoT-23_<tag>.csv file
    Parameters
    ----------
    data-set-tag : str
        The tag to be used to format the csv filename from the data is loaded
        
    Returns
    -------
    X_raw : pandas dataframe
        raw samples for training
    y_raw : pandas dataframe
        raw labels for testing and validating
    """
    return iot_wrangling.get_X_raw_y_raw(data_set_tag)

def make_up_y(y_raw=None):
    """Gets the wrangled values from the label column

    Parameters
    ----------
    y_raw : TYPE, optional
        DESCRIPTION. The default is None.

    Returns
    -------
    y_binary_class_matrix : 
        one-hot zeroed labels matrix

    """
    y_label_encoder = LabelEncoder()
    y_label_encoder.fit(y_raw)
    y_encoded = y_label_encoder.transform(y_raw)
    
    # Converts a class vector (integers) to binary class matrix.
    y_binary_class_matrix = np_utils.to_categorical(y_encoded)
    
    return y_binary_class_matrix
    
def make_up_X(X_raw=None, kind_of_columns=""):
    """Splits the data set
    
    Parameters
    ----------
    kind_of_columns : str
        DESCRIPTION. The default is "".

    Returns
    -------
    selected_X_columns : numpy array
    """
    # duration, orig_bytes, resp_bytes, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes
    scalars_df = iot_wrangling.get_wrangled_column(X_raw, column_name='scalars')
    
    id_resp_p_df = iot_wrangling.get_wrangled_column(X_raw, column_name='id.resp_p')
    proto_df = iot_wrangling.get_wrangled_column(X_raw, column_name='proto')
    service_df = iot_wrangling.get_wrangled_column(X_raw, column_name='service')
    conn_state_df = iot_wrangling.get_wrangled_column(X_raw, column_name='conn_state')
    history_df = iot_wrangling.get_wrangled_column(X_raw, column_name='history')
    
    selected_data_set_npa = []

    # %% selecting features to be use as input (scalars, categorical, or both)
    if 'categorical' == kind_of_columns:
        selected_data_set_df = pd.concat([id_resp_p_df, proto_df, service_df, conn_state_df, history_df], axis=1, sort=False)
        selected_data_set_npa = selected_data_set_df.to_numpy()
    elif 'scalar' == kind_of_columns:
        scaler = StandardScaler()
        selected_data_set_npa = scaler.fit_transform(scalars_df)
    elif 'both' == kind_of_columns:
        scaler = StandardScaler()
        scaled_scalars_npa = scaler.fit_transform(scalars_df)
        selected_data_set_npa = np.concatenate([scaled_scalars_npa,
                                               id_resp_p_df.to_numpy(),
                                               proto_df.to_numpy(),
                                               service_df.to_numpy(),
                                               conn_state_df.to_numpy(),
                                               history_df.to_numpy()],
                                               axis=1)
        
    return selected_data_set_npa
        
def split_data_set(X=None, y=None, split_ratio=0.00):
    """ Splits data set based on ratio parameter
    Parameters
    ----------
    X : numpy array
        X columns. The default is None.
    y : numpy array
        y columns. The default is None.
    split_ratio : float
        Splitting ratio based on command line parameter
    Returns
    -------
    X_train : 
        X_test :
            y_train :
                y_test

    """
    # %% spliting the dataset (holding out the test data subset for validation)
    X_train_valid, X_test, y_train_valid, y_test = train_test_split(X,
                                                                  y,
                                                                  test_size=split_ratio,
                                                                  random_state=42)
    
    # calculating the number of samples for training and validating
    n_validation_samples = int(X_train_valid.shape[0] * split_ratio)
    n_training_samples = X_train_valid.shape[0] - n_validation_samples
    
    # getting the validation samples data set
    X_train, X_valid = X_train_valid[:n_training_samples], X_train_valid[n_training_samples:]
    y_train, y_valid = y_train_valid[:n_training_samples], y_train_valid[n_training_samples:]
    
    return X_train, X_valid, X_test, y_train, y_valid, y_test



# Build neural network
def one_hidden_layer(X_train, X_valid, X_test, y_train, y_valid, y_test, n_hl_nodes=0, batch_size=1, epochs=10, verbose=0):
    n_input_cols = X_train.shape[1]
    
    n_output_cols = y_train.shape[1]
    
    model = Sequential()
    model.add(Dense(n_hl_nodes, input_shape=(n_input_cols,), activation='relu'))
    model.add(Dense(n_output_cols, activation='softmax'))

    # Compile model
    model.compile(optimizer='adam',
                  loss='categorical_crossentropy',
                  metrics=['accuracy'])
    #
    # set early stopping monitor,
    # hence the model will stop training when it does not improve anymore
    
    early_stopping_monitor = EarlyStopping(monitor="val_loss",
                                           mode="min",
                                           restore_best_weights=True,
                                           verbose=1) 

    # Train model
    history = model.fit(X_train, y_train,
              batch_size=batch_size,
              epochs=epochs,
              callbacks=[early_stopping_monitor],
              verbose=verbose,
              validation_data=(X_valid, y_valid))

    # Evaluating the model
    score = model.evaluate(X_test, y_test, verbose=0)

    # loss -> score[0]
    # accuracy -> score[1]
    return score[0], score[1], history

def save_plot(history=None, plot_filename=''):
    plt.plot(history.history['accuracy'])
    plt.plot(history.history['val_accuracy'])
    plt.title('Model Accuracy')
    plt.ylabel('Accuracy')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.grid(True)
    plt.gca().set_ylim(0, 1) # set the vertical range to [0-1]
    plt.savefig('plots/{}.accu.png'.format(plot_filename))
    plt.close()
    
    # Plot training & validation loss values
    plt.plot(history.history['loss'])
    plt.plot(history.history['val_loss'])
    plt.title('model_output loss')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend(['Train', 'Test'], loc='upper left')
    plt.savefig('plots/{}.loss.png'.format(plot_filename))
    plt.close()

# =============================================================================
# # %% evaluation
# y_pred = model.predict(X_test)
# y_pred_rounded = np.around(y_pred)
# multilabel_confusion_matrix(y_test, y_pred_rounded)
# precision_score(y_test, y_pred_rounded, average='weighted')
# =============================================================================

    # 
# %% main


def main():
    X_raw, y_raw = load_data_set(exec_params['data-set-tag'])
    
    X = make_up_X(X_raw, exec_params['kind-of-columns'])
    y = make_up_y(y_raw)    
    
    X_train, X_valid, X_test, y_train, y_valid, y_test = split_data_set(X, y, exec_params['split-ratio'])
    
    n_input_samples = X_train.shape[0]
    
    if 'input'  == exec_params['num-hl-nodes']:
        n_hl_nodes = X_train.shape[1]
    elif 'output'  == exec_params['num-hl-nodes']:
        n_hl_nodes = y_train.shape[1]
    elif 'twice_input'  == exec_params['num-hl-nodes']:
        n_hl_nodes = 2 * X_train.shape[1]
    elif 'twice_output'  == exec_params['num-hl-nodes']:
        n_hl_nodes = 2 * y_train.shape[1]
    elif 'two_thirds_inputs_plus_outputs'  == exec_params['num-hl-nodes']:
        n_hl_nodes = int(2/3 * X_train.shape[1]) + y_train.shape[1]
    elif 'less_than_twice_input'  == exec_params['num-hl-nodes']:
        n_hl_nodes = int(66/100 * X_train.shape[1])
        
    stats_list = []

    print("Parameters: data-set: {}, k_of_columns: {}, ratio: {:f}, nhln: {}".format(
          exec_params['data-set-tag'],
          exec_params['kind-of-columns'],
          exec_params['split-ratio'],
          exec_params['num-hl-nodes']))
    
    # 1, 16, 32, 64, 128, 256, 512, 1024, 2048, n_input_samples
    # 10, 100, 500, 1000, 5000
    for batch_size in [1, 16, 32, 64, 128, 256, 512, 1024, 2048, n_input_samples]:
        for epochs in [10, 100, 500, 1000, 5000]:
            log_msg = 'ds={}, k_cols={}, s_ratio={}, nhln={}, bs={:d}, e={:d},'.format(exec_params['data-set-tag'],
                                                                                   exec_params['kind-of-columns'],
                                                                                   exec_params['split-ratio'],
                                                                                   exec_params['num-hl-nodes'],
                                                                                   batch_size,
                                                                                   epochs)
            ohl_start_time = time.time()
            ohl_start_ts = datetime.datetime.fromtimestamp(ohl_start_time).isoformat()
            print('{} - START - {}'.format(ohl_start_ts, log_msg))
            
            loss, accuracy, history = one_hidden_layer(X_train,
                                                       X_valid,
                                                       X_test,
                                                       y_train,
                                                       y_valid,
                                                       y_test,
                                                       n_hl_nodes=n_hl_nodes,
                                                       batch_size=batch_size,
                                                       epochs=epochs,
                                                       verbose=0)
            ohl_end_time = time.time()
            ohl_elapsed_time = int(ohl_end_time - ohl_start_time)
            
            ohl_end_ts = datetime.datetime.fromtimestamp(ohl_end_time).isoformat()
            print('{} - END - {}, elapsed time: {:d} sec(s)'.format(ohl_end_ts, log_msg, ohl_elapsed_time))

            stats_list.append([ohl_start_ts, ohl_end_ts, ohl_elapsed_time, batch_size, epochs, loss, accuracy])
            
            plot_filename='ohl_ds_{}_k_cols_{}_s_ratio_{:d}_nhln_{}_bs_{:d}_e_{:d}'.format(exec_params['data-set-tag'],
                                                                                           exec_params['kind-of-columns'],
                                                                                           int(exec_params['split-ratio']*100),
                                                                                           exec_params['num-hl-nodes'],
                                                                                           batch_size,
                                                                                           epochs)
  
            save_plot(history, plot_filename)
            # print(ohl_start, ohl_end, batch_size, epochs, loss, accuracy)

    stats_df = pd.DataFrame(stats_list, columns=['ohl_start', 'ohl_end', 'elapsed', 'batch_size', 'epochs', 'loss', 'accuracy'])
    #stats_filename='ohl_ratio_{:d}_features_{}_dataset_{}.csv'
    #stats_filename=stats_filename.format(int(exec_params['split-ratio']*100), exec_params['kind-of-columns'], exec_params['data-set-tag'])
    stats_filename='ohl_ds_{}_k_cols_{}_s_ratio_{:d}_nhln_{}.csv'.format(exec_params['data-set-tag'],
                                                                                           exec_params['kind-of-columns'],
                                                                                           int(exec_params['split-ratio']*100),
                                                                                           exec_params['num-hl-nodes'])
    stats_df.to_csv('stats/'+stats_filename)
    
    return RETURN_OK

# %% _tmp
# =============================================================================
# def _tmp_ric_():
#     for batch_size in [1, 16, 32, 64, 128, 256, 512, 1024, 2048, n_input_samples]:
#         for epochshs in [10, 100, 500, 1000, 5000]:
#             loss, accuracy = one_hidden_layer(batch_size=batch_size,
#                                               epochs=epochs,
#                                               verbose=0)
#             print(batch_size, epochs, loss, accuracy)
# =============================================================================

# %% running as script
if __name__ == "__main__":
    if not os.path.exists('stats'):
        os.makedirs('stats')
    if not os.path.exists('plots'):
        os.makedirs('plots')
        
    parsing_rc = parsing_argv(sys.argv)
    
    if RETURN_OK == parsing_rc:
        sys.exit(main())
    elif RETURN_USAGE == parsing_rc:
        sys.exit(RETURN_OK)
    else:
        sys.exit(RETURN_NOT_OK)
        

# =============================================================================
# rounded = [round(x[0]) for x in y_pred]
# y_pred1 = np.array(rounded,dtype='int64')
#
# from sklearn.metrics import multilabel_confusion_matrix
# from sklearn.metrics import confusion_matrix
# from sklearn.metrics import precision_score
# confusion_matrix(y_test,y_pred1)
# precision_score(y_test,y_pred1)
# =============================================================================

# Calculate the Error and Find the Anomalies!
#get the MSE error term
# =============================================================================
# predictions = autoencoder.predict(scaled_seqs)
# mse = np.mean(np.power(scaled_seqs - predictions, 2), axis=1)
# print('MSE:', np.quantile(mse, 0.9999)) # => the 9999% quatile - only 0.0001% have error score higher than that
#
# =============================================================================


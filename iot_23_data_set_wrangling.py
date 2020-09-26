# -*- coding: utf-8 -*-
"""
Created on Sun Jun 14 14:50:59 2020

@author: Rolando Inglés

"""
import pandas as pd

import iot_23_utils as iotutils


# %% definitions
iot_23_X_selected_columns = ['id.resp_p',
                            'proto',
                            'service',
                            'duration',
                            'orig_bytes',
                            'resp_bytes',
                            'conn_state',
                            'history',
                            'orig_pkts',
                            'orig_ip_bytes',
                            'resp_pkts',
                            'resp_ip_bytes'
                            ]
iot_23_X_selected_scalars_columns = [
                            'duration',
                            'orig_bytes',
                            'resp_bytes',
                            'orig_pkts',
                            'orig_ip_bytes',
                            'resp_pkts',
                            'resp_ip_bytes'
                            ]

iot_23_y_selected_columns = ['tunnel_parents   label   detailed-label']

# =============================================================================
# NOTE: https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html
#
# =============================================================================
# conn_state: string&log&optional
# Possible conn_state values:
# 
# S0: Connection attempt seen, no reply.
# S1: Connection established, not terminated.
# SF: Normal establishment and termination. Note that this is the same symbol as for state S1. You can tell the two apart because for S1 there will not be any byte counts in the summary, while for SF there will be.
# REJ: Connection attempt rejected.
# S2: Connection established and close attempt by originator seen (but no reply from responder).
# S3: Connection established and close attempt by responder seen (but no reply from originator).
# RSTO: Connection established, originator aborted (sent a RST).
# RSTR: Responder sent a RST.
# RSTOS0: Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
# RSTRH: Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
# SH: Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was “half” open).
# SHR: Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
# OTH: No SYN seen, just midstream traffic (a “partial connection” that was not later closed).
# =============================================================================
# history: string&log&optional
#   Records the state history of connections as a string of letters. 
#       The meaning of those letters is:
# 
#           Letter	Meaning
#            s	a SYN w/o the ACK bit set
#            h	a SYN+ACK (“handshake”)
#            a	a pure ACK
#            d	packet with payload (“data”)
#            f	packet with FIN bit set
#            r	packet with RST bit set
#            c	packet with a bad checksum (applies to UDP too)
#            g	a content gap
#            t	packet with retransmitted payload
#            w	packet with a zero window advertisement
#            i	inconsistent packet (e.g. FIN+RST bits set)
#            q	multi-flag packet (SYN+FIN or SYN+RST bits set)
#            ^	connection direction was flipped by Zeek’s heuristic
#       
#       If the event comes from the originator, 
#           the letter is in upper-case; 
#       if it comes from the responder, 
#             it’s in lower-case. 
#       The ‘a’, ‘d’, ‘i’ and ‘q’ flags 
#             are recorded a maximum of one time in either direction 
#             regardless of how many are actually seen. 
#       ‘f’, ‘h’, ‘r’ and ‘s’ can be recorded multiple times 
#             for either direction if the associated sequence number differs 
#             from the last-seen packet of the same flag type. 
#       ‘c’, ‘g’, ‘t’ and ‘w’ are recorded in a logarithmic fashion: 
#             the second instance represents that the event was seen (at least) 
#             10 times; the third instance, 100 times; etc.
# =============================================================================

##
# @name get_data_set
#
# Objective: open CSV file based on the tag and return a dataframe object
#
# Parameters: The tag: 5K 10K 25K 50K 100K 
#
# Returns: raw_X    dataframe to be used as X_train
#           raw_y   dataframe to be used as y_train 
#   
def get_X_raw_y_raw(data_set_tag='notag'):
    data_set_input_filename = iotutils.get_iot_23_output_filename(data_set_tag)
    
    # NOTE: 80 features are loaded
    raw_data_set_df = pd.read_csv(data_set_input_filename)
    raw_X = raw_data_set_df.filter(items=iot_23_X_selected_columns)
    raw_y = raw_data_set_df.filter(items=iot_23_y_selected_columns)
    
    return raw_X, raw_y

##
# @name get_wrangled_id_resp_p
#
# Objective:    Munging the 'id.resp_p' column from the passed IoT-23 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      id_resp_p_df - the dataframe containing the wrangled
#                               'id.resp_p' column data
#                               
def get_ohe_from_id_resp_p(raw_df=None):
    #
    # based on: https://tools.ietf.org/html/rfc1340
    id_resp_p_df = raw_df.loc[:,('id.resp_p')].to_frame()
    id_resp_p_df.rename(columns={'id.resp_p':'_id_resp_p_'}, inplace=True)
    
    # RFC1340: The Registered Ports are in the range 1024-65535
    id_resp_p_df['id.resp_p']='gt_65535'
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ < 65536, 'id.resp_p'] = '1024_65535'
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ < 1024, 'id.resp_p'] = 'lt_1024'
    
    # ssh
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 22, 'id.resp_p'] = 'ssh'
    
    # telnet
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 23, 'id.resp_p'] = 'telnet'
    
    # Message Processing Module [recv]
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 45, 'id.resp_p'] = 'mpm'
    
    # Domain Name Server
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 53, 'id.resp_p'] = 'dns'
    
    # World Wide Web HTTP 
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 80, 'id.resp_p'] = 'http_80'
    
    # ntp
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 123, 'id.resp_p'] = 'ntp'
    
     # https
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 443, 'id.resp_p'] = 'https'
    
     # mdqs
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 666, 'id.resp_p'] = 'mdqs'
    
    # World Wide Web HTTP 
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 8080, 'id.resp_p'] = 'http_8080'
    
    # World Wide Web HTTP 
    id_resp_p_df.loc[id_resp_p_df._id_resp_p_ == 8081, 'id.resp_p'] = 'http_8081'
    
    id_resp_p_df = pd.concat([id_resp_p_df, pd.get_dummies(id_resp_p_df['id.resp_p'], prefix='id.resp_p')], axis=1)
    id_resp_p_df.drop(['id.resp_p'], axis=1, inplace=True)
    id_resp_p_df.drop(['_id_resp_p_'], axis=1, inplace=True)
    
    
# =============================================================================
#     id_resp_p_serie.replace(to_replace='123', value='ntp', inplace=True)
#     id_resp_p_serie.replace(to_replace='23', value='telnet', inplace=True)
# =============================================================================
    return id_resp_p_df

##
# @name get_wrangled_proto
#
# Objective:    Munging the 'proto' column from the passed IoT-23 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      proto_df - the dataframe containing the wrangled
#                               'proto' column data
#                               
def get_ohe_from_proto(raw_df=None):
# 
    # proto
    proto_df = raw_df.loc[:,('proto')].to_frame()
    proto_df = pd.get_dummies(proto_df['proto'], prefix='proto')
    
    return proto_df

##
# @name get_wrangled_service
#
# Objective:    Munging the 'service' column from the passed IoT-23 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      service_df - the dataframe containing the wrangled
#                               'service' column data
#                               
def get_ohe_from_service(raw_df=None):
    # service into one-hot encoding
    service_df = raw_df.loc[:,('service')].to_frame()
    service_df['service'].replace(to_replace=['-'], value='unknown', inplace=True)
    
    service_df = pd.concat([service_df, pd.get_dummies(service_df['service'], prefix='service')], axis=1)
    service_df.drop(['service'], axis=1, inplace=True)
    
    return service_df

##
# @name get_wrangled_conn_state
#
# Objective:    Munging the 'conn_state' column from the passed IoT-23 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      conn_state_df - the dataframe containing the wrangled
#                               'conn_state' column data
#                               
def get_ohe_from_conn_state(raw_df=None):   
    # conn_state into one-hot encoding
    conn_state_df = raw_df.loc[:,('conn_state')].to_frame()
    conn_state_df = pd.get_dummies(conn_state_df['conn_state'], prefix='conn_state')
    
    return conn_state_df
    
##
# @name get_wrangled_history
#
# Objective:    Munging the 'history' column from the passed IoT-23 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      history_df - the dataframe containing the wrangled
#                               'history' column data
#                               
def get_ohe_from_history(raw_df=None):    
    # history
    #       a SYN w/o the ACK bit set
    history_df = raw_df.loc[:,('history')].to_frame()
    
    history_df['history_Ss'] = history_df['history'].replace(regex='[Ss]', value=1)
    history_df['history_Ss'].replace(regex='[^1]', value=0, inplace=True)

    #       a SYN+ACK (“handshake”)
    history_df['history_Hh'] = history_df['history'].replace(regex='[Hh]', value=1)
    history_df['history_Hh'].replace(regex='[^1]', value=0, inplace=True)
    
    #       a pure ACK
    history_df['history_Aa'] = history_df['history'].replace(regex='[Aa]', value=1)
    history_df['history_Aa'].replace(regex='[^1]', value=0, inplace=True)
    
    #       packet with payload (“data”)
    history_df['history_Dd'] = history_df['history'].replace(regex='[Dd]', value=1)
    history_df['history_Dd'].replace(regex='[^1]', value=0, inplace=True)
    
    #       packet with FIN bit set
    history_df['history_Ff'] = history_df['history'].replace(regex='[Ff]', value=1)
    history_df['history_Ff'].replace(regex='[^1]', value=0, inplace=True)
    
    #       packet with RST bit set
    history_df['history_Rr'] = history_df['history'].replace(regex='[Rr]', value=1)
    history_df['history_Rr'].replace(regex='[^1]', value=0, inplace=True)
    
    #       packet with a bad checksum (applies to UDP too)
    history_df['history_Cc'] = history_df['history'].replace(regex='[Cc]', value=1)
    history_df['history_Cc'].replace(regex='[^1]', value=0, inplace=True)
    
    #       a content gap
    history_df['history_Gg'] = history_df['history'].replace(regex='[Gg]', value=1)
    history_df['history_Gg'].replace(regex='[^1]', value=0, inplace=True)
    
    #       packet with retransmitted payload
    history_df['history_Tt'] = history_df['history'].replace(regex='[Tt]', value=1)
    history_df['history_Tt'].replace(regex='[^1]', value=0, inplace=True)
    
    #       packet with a zero window advertisement
    history_df['history_Ww'] = history_df['history'].replace(regex='[Ww]', value=1)
    history_df['history_Ww'].replace(regex='[^1]', value=0, inplace=True)
    
    #       inconsistent packet (e.g. FIN+RST bits set)
    history_df['history_Ii'] = history_df['history'].replace(regex='[Ii]', value=1)
    history_df['history_Ii'].replace(regex='[^1]', value=0, inplace=True)
    
    #       multi-flag packet (SYN+FIN or SYN+RST bits set)
    history_df['history_Qq'] = history_df['history'].replace(regex='[Qq]', value=1)
    history_df['history_Qq'].replace(regex='[^1]', value=0, inplace=True)
    
    #       connection direction was flipped by Zeek’s heuristic
    history_df['history_conn_flip'] = history_df['history'].replace(regex='[.^]', value=1)
    history_df['history_conn_flip'].replace(regex='[^1]', value=0, inplace=True)

    #       - dash -
    history_df['history_unknown'] = history_df['history'].replace(to_replace=['-'], value=1)
    history_df['history_unknown'].replace(regex='[^1]', value=0, inplace=True)
    
    history_df.drop(['history'], axis=1, inplace=True)
    
    return history_df

##
# @name get_wrangled_scalars
#
# Objective:    Munging columns with scalar content from the passed IoT-23 
#               raw data frame
#
# Parameters:
#               raw_df - the dataframe containing the raw column data
#                           to be wrangled
#
# Returns:      scalars_df - the dataframe containing the wrangled
#                               'scalars' columns data
#                               
def get_wrangled_scalars(raw_df=None): 
    scalars_df = raw_df.filter(items=iot_23_X_selected_scalars_columns)
     
    # duration
    scalars_df['duration'].replace(to_replace=['-'], value=0, inplace=True)
    
    # orig_bytes
    scalars_df['orig_bytes'].replace(to_replace=['-'], value=0, inplace=True)
    
    # orig_bytes
    scalars_df['resp_bytes'].replace(to_replace=['-'], value=0, inplace=True)
    
    return scalars_df

##
# @name get_wrangled_column
#
# Objective: having opened the data set source file, filtering the column
#               base on the column_name parameter, then the munging process
#               is performed over the filtered column data 
#
# Parameters: 
#               raw_df - dataframe containing the raw column data from where
#                        the munging data will be performed
#               column_name - the name of the column  
#
# Returns: dataframe 
#   
def get_wrangled_column(raw_df=None, column_name='__no_name__'):
    if 'id.resp_p' == column_name:
        return get_ohe_from_id_resp_p(raw_df)
    elif 'proto' == column_name:
        return get_ohe_from_proto(raw_df)
    elif 'service' == column_name:
        return get_ohe_from_service(raw_df)
    elif 'conn_state' == column_name:
        return get_ohe_from_conn_state(raw_df)
    elif 'history' == column_name:
        return get_ohe_from_history(raw_df)
    elif 'scalars' == column_name:
        return get_wrangled_scalars(raw_df)
    
# %% __main__
if __name__ == '__main__':
    print("it's a library, please use it by importing")


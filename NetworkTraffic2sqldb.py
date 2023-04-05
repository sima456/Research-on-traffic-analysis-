import numpy as np
import pandas as pd
import pyshark
import sqlite3
from sqlite3 import Error
import statistics 
import os
import nest_asyncio
nest_asyncio.apply()

# table definition
sql_table= """CREATE TABLE IF NOT EXISTS sqllite_table(
		file_name varchar(50) NOT NULL,
		session_number integer NOT NULL,
		session_ttl_min varchar(10) NOT NULL,
		session_packets integer NOT NULL,
		session_packet_size_avg varchar(10) NOT NULL,
		session_tcp_analysis_retransmission integer NOT NULL,
		session_tcp_analysis_duplicate_ack integer NOT NULL
	);"""

# creating connection 
def create_connection(db_file):
    """ create a database connection to a SQLite database """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
        #print(sqlite3.version)
    except Error as e:
        print(e)

# create table function
def create_table(conn, sql_table):
	try:
		cur = conn.cursor()
		cur.execute(sql_table)
	except Exception as e:
		print(e)

# insert into table
def create_entry(conn, task):
    sql = """INSERT INTO sqllite_table(file_name,session_number,session_ttl_min,session_packets,session_packet_size_avg,session_tcp_analysis_retransmission,session_tcp_analysis_duplicate_ack)
			VALUES(?,?,?,?,?,?,?)"""
    cur = conn.cursor()
    cur.execute(sql,task)
    return cur.lastrowid


# create connection
conn = create_connection(r"pythonsqlite.db")
# create table
if conn:
	create_table(conn, sql_table)

files = ['iot1_new.pcap','iot2_new.pcap']
for i in files:
	session_number=[]
		# find the max session **** this can be used to get all session *****
	captures = pyshark.FileCapture(i)
	for pkts in captures:
		session_number.append(int(pkts.tcp.stream))
	total_sessions=max(session_number)
	#printing total number of sessions

	print(" Total sessions in file {}: {} ".format(i,total_sessions))
	for session in range(total_sessions):	
		capture = pyshark.FileCapture(i,display_filter='tcp.stream eq {}'.format(session))
		# size of packet
		packet_len=0
		retransmission=0
		dup_ack=0
		packet_count=0
		tcp_packet_count=0
		# to hold ttl of each packet
		ttl=[]
		median=0
		pckt_avg=0
		#print("**** Session : {} ****\n".format(session))
		for pkt in capture:
			if int(pkt.tcp.stream) == session:
				# count total packets in this session 
				packet_count+=1
				# storing ttl of this packet
				ttl.append(int(pkt.ip.ttl))
				# count packets with protocl == tcp
				if int(pkt.ip.proto) == 6:
					tcp_packet_count+=1
				# sum packets length 
				packet_len+=int(pkt.length)
				# finding total number of retransmitted packets in each session
				if "analysis_retransmission" in pkt.tcp.field_names:
					retransmission+=1
				# finding number of duplicate ack packets
				if "analysis_duplicate_ack" in pkt.tcp.field_names:
					dup_ack+=1
		mint = min(ttl)
		pckt_avg = packet_len/packet_count

	# inserting data
		with conn:
			row = (i,session,mint,packet_count,pckt_avg,retransmission,dup_ack)
			insert_r = create_entry(conn, row)

	# print table
print(pd.read_sql_query("SELECT * FROM sqllite_table", conn))
conn.close()

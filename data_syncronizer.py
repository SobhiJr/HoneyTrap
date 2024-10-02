import pandas as pd
import requests 
import socket 
import sqlalchemy as sqla 
import sqlite3
#hader interface


server_ip='192.168.11.11'
sensor_ip='192.168.11.33' 
webserver_ip='192.168.11.32'

local_IPs={'server_ip':'192.168.11.11','sensor_ip':'192.168.11.33','webserver_ip':'192.168.11.32'}

#DATA SYNCRONIZATION CLASS

class DataSyncronizer:
	#LOCAL_VARIABLES
	csv=" "
	ipdf=pd.DataFrame()
	data=pd.DataFrame()
	last_time=pd.to_datetime('2024-01-01 00:00:00')
	coon=None
	local_IPs={}
	ips={}
	data_n=0
	
	
	#CONSTRUCTOR
	#Initiating the values
	def __init__(self,coon,out_database):
		self.coon=coon
#		try:
#			self.ipdf=pd.read_sql('select * from ipdf',out_database)
#
#		except:
#			print(f"IP database has not created yet .")
#			self.ipdf=pd.DataFrame()

		self.db=out_database
		coonn=sqlite3.connect(self.db)
		cur=coonn.cursor()
		cur.execute('DROP TABLE IF EXISTS honeytrap;')
		cur.execute('DROP TABLE IF EXISTS plugin;')
		cur.execute('DROP TABLE IF EXISTS ipdf;')
		
		extra_data = pd.read_sql(qry5,self.coon)
		extra_data.to_sql('plugin',con=coonn,if_exists='replace',index=False)
		coonn.close()
		print("database has been droped")
		
	#GET_COORDINATES
	#Getting coordinates form ip2location API
	def get_coordinates_from_ip(self,ip_address):
		self.base_url = f"https://api.ip2location.io/?key=48A3CC41C81A3372BA0CA52D8851508F&ip={ip_address}"
		if ip_address.startswith('192.168.11.'):
			self.base_url='https://api.ip2location.io/'

		try:
			response = requests.get(self.base_url)
			data = response.json()

			if "latitude" in data and "longitude" in data:
				country = data['country_name']
				region	 = data['region_name']
				city	 = data['city_name']
				latitude= data['latitude']
				longitude= data['longitude']
				isp = data['as']
				is_proxy = data['is_proxy']
				return latitude, longitude ,country,city,region,isp,is_proxy
			else:
				print("Unable to retrieve coordinates.")
				return None,None,None,None,None,None,None
				
		except requests.exceptions.RequestException as e:
			print(f"Error: {e}")
			return None,None,None,None,None,None,None
	#IP_CHECK
	#checking if the ip is already exists in the system		
	def ip_check(self,ip_address):
		conn=sqlite3.connect(self.db)
		if not self.ipdf.empty:
			if ip_address in self.ipdf['ip'].values:
				print('this ip is already exist!')
			else:
				coor = self.get_coordinates_from_ip(ip_address)
				ip = pd.DataFrame({'ip': [ip_address], 'lat': coor[0], 'lon': coor[1], 'country': coor[2], 'city': coor[3],'region':coor[4],'isp':coor[5],'is_proxy':coor[6]})
#				ip.to_csv('ipdf.csv', mode='a', header=False, index=False)
				ip.to_sql('ipdf',con=conn,if_exists='append',index=False)
				self.ipdf=pd.read_sql('select * from ipdf;',conn)
		else :

			coor = self.get_coordinates_from_ip(ip_address)
			ip = pd.DataFrame({'ip': [ip_address], 'lat': coor[0], 'lon': coor[1], 'country': coor[2], 'city': coor[3],'region':coor[4],'isp':coor[5],'is_proxy':coor[6]})
#			ip.to_csv('ipdf.csv', mode='a', header=True, index=False)
			ip.to_sql('ipdf',con=conn,if_exists='append',index=False)
			self.ipdf=pd.read_sql('select * from ipdf;',conn)

	#ETL FUNCTIONS 
	
	
	#EXTRACT FUNCTION
	#extracting data from OSSIMServer Database
	def extract(self):
		print('extract process starts')
		data=pd.DataFrame()
		#result=pd.read_csv('events.csv')	
		last_time=self.last_time
		print(last_time)
		result = pd.read_sql(qry2,coon)
		result_len =result[ 'count(*)' ][0]
		print(result_len,"------",self.data_n)
		if result_len > self.data_n:
			limit=result_len-self.data_n
			if limit > 500:
                           limit = 500
			qry8=f"SELECT * FROM acid_event ORDER BY timestamp DESC LIMIT {limit};"
			data = pd.read_sql(qry8,self.coon)
			data=data.sort_values(by='timestamp',ascending=True)
			
			print(f'there are new : ({len(data)}) rows')
			self.last_time=data.timestamp.iloc[-1]
			self.data_n += len(data)
			print(f'time has been updated to :{self.last_time}')
			print('extract process ends')
			return data.reset_index()
		else:
			print('NO NEW DATA FOUNDED')
	
			return data
	
	
	#DATA TRANSFORMATION		
	#transforming and establish the preprocessing of data
	
	def transform(self,data):
		print('transform process starts')
		l=len(data.ip_src)
		for i in range(l):
			s_ip=data.ip_src[i]
			d_ip=data.ip_dst[i]
			if str(s_ip) in self.ips.keys():
				data.ip_src[i]=self.ips[str(s_ip)]
			else:
				if len(s_ip) == 4:
					data.ip_src[i]=socket.inet_ntoa(s_ip)
					self.ips[str(s_ip)]=data.ip_src[i]
					self.ip_check(data.ip_src[i])
			
			
			if str(d_ip) in self.ips.keys():
				data.ip_dst[i]=self.ips[str(d_ip)]
			else:
				if len(d_ip) == 4:
					data.ip_dst[i]=socket.inet_ntoa(d_ip)
					self.ips[str(d_ip)]=data.ip_dst[i]
					self.ip_check(data.ip_dst[i])
				
	
		data.timestamp=pd.to_datetime(data.timestamp)
		print('transform process ends')
		return data
	#LOAD DATA
	#loading data into the csv file	
	def load(self,data):
		final_data=data[['id','timestamp','ip_src','ip_dst','ip_proto','layer4_sport','layer4_dport','ossim_priority','ossim_reliability','ossim_asset_src','ossim_asset_dst','ossim_risk_c','ossim_risk_a','plugin_id','plugin_sid','tzone','ossim_correlation','src_hostname','dst_hostname']]

		conn = sqlite3.connect(self.db)
		final_data.to_sql('honeytrap',con=conn,if_exists='append',index=False)
		conn.commit()		


url = f"mysql+mysqlconnector://root:qbUhTNqBx6@{server_ip}/alienvault_siem"
cooon=sqla.create_engine(url)
coon=cooon.connect()

qry = "select user();"
qry2 = "select count(*) from acid_event;"
qry3 = 'SHOW TABLES;'
qry4 = "select * from acid_event order by timestamp asc;"
qry5=f"select id,name,vendor,description from alienvault.plugin;"

qry7 = "select * from acid_event order by timestamp desc limit 1000;"


csvfile='event.csv'

sync=DataSyncronizer(coon,'data.db')

while True:
	data=sync.extract()
	if data.empty:
		continue
	data=sync.transform(data)
	sync.load(data)

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import dash
import dash.dcc as dcc
import dash.html as html
from dash.dependencies import State, Input, Output
from dash import dash_table
import dash_daq as daq
from ping3 import ping
import sqlite3
import pytz
#hader interface
app = dash.Dash(
    __name__,
    meta_tags=[
        {"name": "HONEY TRAP", "content": "width=device-width, initial-scale=1.0"}
    ],
)
result=pd.DataFrame()
server = app.server




def execute(qry):
	coonn=sqlite3.connect('data.db')
	data=pd.read_sql(qry,coonn)
	coonn.close()

	return data


#local IPs

server_ip='192.168.11.11'
sensor_ip='192.168.11.33'
webserver_ip='192.168.11.32'
honeyput_ip='192.168.11.22'

global_ip='192.168.11.22'



qry_log_count=f"select count(*) from honeytrap WHERE ip_dst = '{global_ip}' OR ip_src = '{global_ip}';"
qry_server_counter = f"select count(*) from honeytrap where ip_src = '{global_ip}' or ip_dst='{global_ip}';"
qry4 = "select * from acid_event order by timestamp asc;"
qry3 = 'SHOW TABLES;'

frequency=1000
#data=extract(qry5)
ipdf=execute(f"SELECT * FROM ipdf WHERE ip = '{global_ip}' OR ip = '{global_ip}';")
#print(type(update_data(intervals)))
log_count = html.Div(
    id="log_count",
    children=[
        daq.LEDDisplay(
            id="log_counter",
            label="LOGs NUMBER",
	    value='165',
            size=40,
            color="#fec036",
            backgroundColor="#2b2b2b",
        )
    ],
    n_clicks=0,
)
green='#39E01B'
yellow="#fec036"
red='#EF483E'
def ping_ind(ip):
	y=ping(ip,timeout=.5)
	if y in [False,None]:
		return red
	else:
		return green

def update_src_bar():
    coonn=sqlite3.connect('data.db')
    src_data=pd.read_sql(f"select ip_src as ip,count(*) as src_n from honeytrap group by ip_src having ip_src LIKE '{global_ip}'",coonn)
    dst_data = pd.read_sql(f"select ip_dst as ip,count(*) as dst_n from honeytrap group by ip_dst having ip_dst LIKE '{global_ip}'", coonn)
    coonn.close()
    src_data.ip=src_data.ip.astype('str')
    dst_data.ip=dst_data.ip.astype('str')
    data = src_data.merge(dst_data, on='ip',how='outer').fillna(0)
    bar=px.bar(data,y='ip',x=['src_n','dst_n'],orientation='h',barmode='group',text_auto=True,template='plotly_dark',color_discrete_sequence=['#1dbac5','#e6f4f5'],log_x=True)
    bar.update_traces(textfont_size=12, textangle=0, textposition="outside", cliponaxis=False)
    bar.update_layout(height=300
    )
    return bar



webserver_ind = daq.Indicator(
    className="panel-lower-indicator",
    id="webserver_ind",
    label="WebServer",
    labelPosition="bottom",
    value=True,
    color="#fec036",
    style={"color": "#black"},
)
server_ind = daq.Indicator(
    className="panel-lower-indicator",
    id="server_ind",
    label="OSSIM Server",
    labelPosition="bottom",
    value=True,
    color="#fec036",
    style={"color": "#black"},
)
sensor_ind = daq.Indicator(
    className="panel-lower-indicator",
    id="sensor_ind",
    label="OSSIM Sensor",
    labelPosition="bottom",
    value=True,
    color="#fec036",
    style={"color": "#black"},
)
honey_ind = daq.Indicator(
    className="panel-lower-indicator",
    id="honey_ind",
    label="HONEYPUT Sensor",
    labelPosition="bottom",
    value=True,
    color="#fec036",
    style={"color": "#black"},
)

log_bars = html.Div(
    id="server_bar",
    children=[
        daq.GraduatedBar(
            id="ossim_server_bar",
            label="OSSIM-Server logs",
            value=85,
            step=1,
           # showCurrentValue=True,
            color="#fec036",
            style={"color": "#black"},
        )
        ,

        daq.GraduatedBar(
            id="sensor_bar",
            label="OSSIM-Sensor logs",
            value=85,
            step=1,
            #showCurrentValue=True,
            color="#fec036",
            style={"color": "#black"},)

    ],
)
risk_gauge= daq.Gauge(
            size=165,
            id="risk_guage",
            label="Current RISK",
            min=0,
            max=5,
            showCurrentValue=True,
            value=5,
            color="#1dbac5",
        )
def update_map():
    MAPBOX_ACCESS_TOKEN = "pk.eyJ1IjoiZ29vLTA5IiwiYSI6ImNscThtcHl2NzE0MXUyanA3N3lyaDV6Y2EifQ.7YguU84rVaFXRo2wm3bYRw"
    MAPBOX_STYLE = "mapbox://styles/goo-09/clq8mts9g004801o9fys04k8z"
    mapbox_access_token = "pk.eyJ1IjoicGxvdGx5bWFwYm94IiwiYSI6ImNrOWJqb2F4djBnMjEzbG50amg0dnJieG4ifQ.Zme1-Uzoi75IaFbieBDl3A"
    mapbox_style = "mapbox://styles/plotlymapbox/cjvprkf3t1kns1cqjxuxmwixz"
    coor=execute("SELECT * FROM ipdf;")
    coor.lat=pd.to_numeric(coor.lat)
    coor.lon=pd.to_numeric(coor.lon)
    coor.is_proxy=coor.is_proxy.astype(bool)

    mapbox2=px.scatter_mapbox(coor,lat='lat',lon='lon',hover_data=['ip',	'lat',	'lon',	'country'	,'city',	'region'	,'isp'	,'is_proxy'],color='is_proxy')
    mapbox2.update_layout(margin=dict(l=5, r=5, t=5, b=5),
        paper_bgcolor="LightSteelBlue",
    )
    map=go.Figure(mapbox2)
    map.update_layout(
        mapbox = {
            'accesstoken':MAPBOX_ACCESS_TOKEN,
            'style': 'dark', 'zoom': 1},
        showlegend =False)
    return map
map=update_map()
#map.add_trace(mapbox2)
def update_timestamp():
    time_data = execute(f"select count(*) as n_log, timestamp as time from honeytrap WHERE ip_dst = '{global_ip}' OR ip_src = '{global_ip}' group by timestamp order by timestamp desc limit 9;")
    time_data['time'] = pd.to_datetime(time_data['time'])
    time_data['time'] += pd.to_timedelta(2, unit='h')
    timestamp = px.line(time_data, x='time', y='n_log', template='plotly_dark', color_discrete_sequence=['#1dbac5', '#e6f4f5'], line_shape='spline')
    timestamp.update_yaxes(range=[0, 100])
    return timestamp

timestamp=update_timestamp()


########################################
def event_table():
    df = execute(f"select * from honeytrap as h left join plugin as p on h.plugin_id=p.id WHERE h.ip_dst = '{global_ip}' OR h.ip_src = '{global_ip}' order by timestamp desc limit 500;")
    df= df.drop_duplicates(subset=['ip_src','ip_dst','timestamp','name'])
#df.data_payload=df.data_payload.to_string()
    df=df[['name','description','vendor','ip_src','ip_dst','timestamp']][:13]
# add an id column and set it as the index
# in this case the unique ID is just the country name, so we could have just
# renamed 'country' to 'id' (but given it the display name 'country'), but
# here it's duplicated just to show the more general pattern.
    event_table = html.Div([
        dash_table.DataTable(
            id='events',
            columns=[
                {'name': i, 'id': i, 'deletable': True} for i in ['name','ip_src','ip_dst','timestamp']
            # omit the id column
                if i != 'id'
            ],
            data=df.to_dict('records'),
            editable=False,
            sort_mode='multi',
            page_action='native',
            page_current= 0,
            page_size= 13,
            style_cell={'textAlign': 'left','padding_left':'20px','padding_right':'20px'}
            ,style_header={
            'backgroundColor': '#1D1B1B','font-weight': 'bold','height':'70px','border':'None','border-radius':'10%',
            'color': 'white'
            ,'border':'none'
            },
            style_data={
            'backgroundColor': 'rgb(50, 50, 50)',
            'color': 'white'
            }
        )
    ])
    return event_table

###########################################################
def top_events():
    df = execute(f"select p.name as name , h.number as number from(select plugin_id ,count(*) as number from honeytrap WHERE ip_dst = '{global_ip}' OR ip_src = '{global_ip}' group by plugin_id order by number desc limit 13) h left join (select id , name from plugin) p on h.plugin_id = p.id")
#    df2= execute("select id ,name from plugin")
#    df= pd.merge(df, df2, left_on='plugin_id', right_on='id')
    df=df[['name','number']]
    event_table = html.Div([
    dash_table.DataTable(
            id='top_events',
            columns=[
                {'name': i, 'id': i, 'deletable': True} for i in ['name','number']
            # omit the id column
                if i != 'id'
            ],
            data=df.to_dict('records'),
            editable=False,
            sort_mode='multi',
            page_action='native',
            page_current= 0,
            page_size= 13,
            style_cell={'textAlign': 'left','padding_left':'20px','padding_right':'20px'}
            ,style_header={
            'backgroundColor': '#1D1B1B','font-weight': 'bold','height':'70px','border':'None','border-radius':'10%',
            'color': 'white'
            ,'border':'none'
            },
            style_data={
            'backgroundColor': 'rgb(50, 50, 50)',
            'color': 'white'
            }
        )
    ])
    return event_table

root_layout=html.Div(children=[html.Div(
    children=[
                html.Div(
                    children=[
                        html.Div(children=[html.Img(src=dash.get_asset_url('light.png'),style={'width':'150px'})]
                                 ,id='logo')
                    ]
                    ,id='header'
                )
                ,html.Div(children=[
                                        html.Div(children=[
                                                            html.Div(
                                                                    children=[
                                                                                html.Div(children=[
                                                                                                    html.Div(children=[html.Div(children=[html.Div(children=[],id='blue_circle',style={'background-color':'#92E36B','border-radius':'50%','width':'15px','height':'15px','margin-right':'30px'}),html.P('LOW RISK'),html.P('0',id='low_risk_val',style={'margin-left':'50px'})],id='low_risk',style={'display':'flex','justify-content': 'left','align-items': 'center','background-color':'#0E0E0E','margin':'10px','padding-left':'20px','padding-right':'20px','border-radius':'13px'})]) ,
                                                                                                    html.Div(children=[html.Div(children=[html.Div(children=[],id='yellow_circle',style={'background-color':'#FFCE51','border-radius':'50%','width':'15px','height':'15px','margin-right':'30px'}),html.P('MEDIUM RISK'),html.P('0',id='medium_risk_val',style={'margin-left':'50px'})],id='medium_risk',style={'display':'flex','justify-content': 'left','align-items': 'center','background-color':'#0E0E0E','margin':'10px','padding-left':'20px','padding-right':'20px','border-radius':'13px'})]),
                                                                                                    html.Div(children=[html.Div(children=[html.Div(children=[],id='red_circle',style={'background-color':'#F1330F','border-radius':'50%','width':'15px','height':'15px','margin-right':'30px'}),html.P('HIGH RISK',style={'padding-right':'25px'}),html.P('0',id='high_risk_val',style={'margin-left':'50px'})],id='high_risk',style={'display':'flex','justify-content': 'left','align-items': 'center','background-color':'#0E0E0E','margin':'10px','padding-left':'20px','padding-right':'20px','border-radius':'13px'})])
                                                                                ] ,
                                                                                                    id='risk_cat',style={'align-items': 'center','margin-top':'40px'}),
                                                                                                    html.Div(children=[ risk_gauge

                                                                                                    ],
                                                                                                    id='risk_level',style={'background-color':'#0E0E0E','margin-top':'30px','padding-top':'10px','padding-buttom':'15px','padding-left':'20px','padding-right':'20px','border-radius':'20px','height':'230px'})
                                                                                ],
                                                                                         id='risk_container',style={'background-color':'#1D1C2C','padding-buttom':'30px','padding-top':'0px','border-radius':'20px','margin-right':'20px'}),
                                                                                html.Div(children=[html.Div(children=[webserver_ind,honey_ind,server_ind,sensor_ind])

                                                                                ],
                                                                                         id='servers_indicators',style={'background-color':'#1D1C2C','padding-buttom':'30px','padding-top':'0px','border-radius':'20px','margin-right':'20px'})
                                                                    ],
                                                                    id='c1_left'
                                                            ),
                                                            html.Div(
                                                                    children=[dcc.Graph(id='map-chart',figure=map)],
                                                                    id='map'

                                                            ),
                                                            html.Div(
                                                                    children=[
                                                                        html.Div(children=[dcc.Graph(id='bars')

                                                                        ],
                                                                        id='bar_chart'),
                                                                        html.Div(children=[log_count

                                                                        ],
                                                                        id='logs_counter')
                                                                    ],
                                                                    id='c1_right'
                                                            )
                                        ]
                                                 ,id='container1'),
                                        html.Div(
                                                children=[
                                                    html.Div(children=[dcc.Graph(id='line',figure=timestamp)]
                                                             ,id='line_chart'),
                                                    html.Div(children=[event_table()]
                                                             ,id='event_table'),
                                                    html.Div(children=[top_events()]
                                                             ,id='top_event')







                                                ],
                                            id='container2'
                                        )
                ],
                          id='body'),dcc.Interval('interval',frequency)] ,id='main'




)


app.layout=root_layout



@app.callback(
Output('log_counter','value')
, Input('interval','n_intervals')
)

def update_data(n_intervals):
	#result = pd.read_sql(qry2,coon)
	#x = str( result[ 'count(*)' ][0] )
	x=execute(qry_log_count)
	x=str(x[ 'count(*)' ][0])
	return x

@app.callback(
Output('webserver_ind','color')
, Input('interval','n_intervals')
)
def update_data2(n_intervals):
	y=ping_ind(webserver_ip)
	return y

@app.callback(
Output('server_ind','color')
, Input('interval','n_intervals')
)
def update_data3(n_intervals):
	y=ping_ind(server_ip)
	return y

@app.callback(
Output('sensor_ind','color')
, Input('interval','n_intervals')
)
def update_data4(n_intervals):
	y=ping_ind(sensor_ip)
	return y

@app.callback(
Output('honey_ind','color')
, Input('interval','n_intervals')
)
def update_data4(n_intervals):
	y=ping_ind(honeyput_ip)
	return y

@app.callback(
Output('bars','figure')
, Input('interval','n_intervals')
)
def update_bars(n_intervals):
	return update_src_bar()

@app.callback(
Output('risk_guage','value')
, Input('interval','n_intervals')
)
def update_risk(n_intervals):
    x=execute(f"select MAX(ossim_risk_c) as risk from honeytrap WHERE ip_dst = '{global_ip}' OR ip_src = '{global_ip}';")
    return x['risk'][0]

@app.callback(
Output('low_risk_val','children')
, Input('interval','n_intervals')
)
def update_risk(n_intervals):
    x=execute(f"select count(*) as risk from honeytrap where ossim_risk_c = 0 AND (ip_dst = '{global_ip}' OR ip_src = '{global_ip}')")
    return str(x['risk'][0])


@app.callback(
Output('medium_risk_val','children')
, Input('interval','n_intervals')
)
def update_risk(n_intervals):
    x=execute(f"select count(*) as risk from honeytrap where ossim_risk_c > 0 and ossim_risk_c <= 3 AND (ip_dst = '{global_ip}' OR ip_src = '{global_ip}')")
    return str(x['risk'][0])


@app.callback(
Output('high_risk_val','children')
, Input('interval','n_intervals')
)
def update_risk(n_intervals):
    x=execute(f"select count(*) as risk from honeytrap where ossim_risk_c > 3 AND (ip_dst = '{global_ip}' OR ip_src = '{global_ip}')")
    return str(x['risk'][0])

@app.callback(
Output('line','figure')
, Input('interval','n_intervals')
)
def update_bars(n_intervals):
	fig= update_timestamp()
	return fig
@app.callback(
Output('map-chart','figure')
, Input('interval','n_intervals')
)
def update_map_chart(n_intervals):
	fig= update_map()
	return fig
@app.callback(
Output('events','data')
, Input('interval','n_intervals')
)
def update_event_table(n):
    df = execute(f"select * from honeytrap as h left join plugin as p on h.plugin_id=p.id WHERE h.ip_dst = '{global_ip}' OR h.ip_src = '{global_ip}' order by timestamp desc limit 500;")
    df= df.drop_duplicates(subset=['ip_src','ip_dst','timestamp','name'])
#df.data_payload=df.data_payload.to_string()
    df=df[['name','ip_src','ip_dst','timestamp']][:13]
    return df.to_dict('records')

@app.callback(
Output('top_events','data')
, Input('interval','n_intervals')
)
def update_event_table(n):
    df = execute(f"select plugin_id ,count(*) as number from honeytrap WHERE ip_dst = '{global_ip}' OR ip_src = '{global_ip}' group by plugin_id order by number desc limit 13")
    df2= execute("select id ,name from plugin")
    df= pd.merge(df, df2, left_on='plugin_id', right_on='id')
    df=df[['name','number']]
    return df.to_dict('records')

if __name__ == "__main__":
    app.run_server(port=8060)
    app.run_server(debug=True,host='127.0.0.1')
    	

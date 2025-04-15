import dash
from dash import dcc, html, dash_table, callback_context
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
from datetime import datetime, timedelta
import dash_bootstrap_components as dbc
import time
import os
from collections import defaultdict
import numpy as np

# Initialize the Dash app with a Bootstrap theme
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG])
server = app.server

# Custom styling
CARD_STYLE = {
    'borderRadius': '10px',
    'boxShadow': '0 4px 8px 0 rgba(0, 0, 0, 0.2)',
    'padding': '15px',
    'backgroundColor': '#1e2130',
    'color': 'white'
}

HEADER_STYLE = {
    'textAlign': 'center',
    'color': '#00ff99',
    'marginBottom': '30px',
    'fontFamily': 'Arial, sans-serif',
    'textShadow': '0 0 5px #00ff99'
}

FILTER_STYLE = {
    'backgroundColor': '#2a2e3f',
    'color': 'white',
    'borderRadius': '5px',
    'padding': '10px',
    'marginBottom': '15px'
}

# Function to load and process data
def load_data():
    # Load attack logs
    if os.path.exists('honeypot_logs.json'):
        with open('honeypot_logs.json') as f:
            attack_logs = json.load(f)
    else:
        attack_logs = []
    
    # Load session logs
    if os.path.exists('honeypot_accessed_section.json'):
        with open('honeypot_accessed_section.json') as f:
            session_logs = json.load(f)
    else:
        session_logs = []
    
    # Process attack logs
    processed_attacks = []
    for entry in attack_logs:
        processed_entry = {
            'timestamp': entry.get('timestamp'),
            'attacker_ip': entry.get('attacker_ip'),
            'attack_type': entry.get('attack_type', 'Unknown'),
            'confidence_level': entry.get('confidence_level', 0),
            'user_agent': entry.get('user_agent', 'Unknown'),
            'action_taken': entry.get('action_taken', 'None'),
            'sqli_possibility': entry.get('sqli_possibility', 'Unknown')
        }
        
        # Extract username and password from payload if exists
        payload = entry.get('payload', {})
        if isinstance(payload, dict):
            processed_entry['username'] = payload.get('username', 'N/A')
            processed_entry['password'] = payload.get('password', 'N/A')
        else:
            processed_entry['username'] = 'N/A'
            processed_entry['password'] = 'N/A'
        
        # Extract browser from user agent
        user_agent = processed_entry['user_agent'].lower()
        if 'chrome' in user_agent:
            processed_entry['browser'] = 'Chrome'
        elif 'firefox' in user_agent:
            processed_entry['browser'] = 'Firefox'
        elif 'safari' in user_agent:
            processed_entry['browser'] = 'Safari'
        else:
            processed_entry['browser'] = 'Other'
        
        # Calculate threat level
        confidence = float(processed_entry['confidence_level']) if str(processed_entry['confidence_level']).replace('.', '').isdigit() else 0
        if confidence > 0.9:
            processed_entry['threat_level'] = 'Critical'
        elif confidence > 0.7:
            processed_entry['threat_level'] = 'High'
        elif confidence > 0.5:
            processed_entry['threat_level'] = 'Medium'
        else:
            processed_entry['threat_level'] = 'Low'
            
        processed_attacks.append(processed_entry)
    
    # Convert to DataFrames
    df_attacks = pd.DataFrame(processed_attacks)
    df_sessions = pd.DataFrame(session_logs)
    
    # Data preprocessing
    if not df_attacks.empty:
        df_attacks['timestamp'] = pd.to_datetime(df_attacks['timestamp'])
        df_attacks['hour'] = df_attacks['timestamp'].dt.hour
        df_attacks['date'] = df_attacks['timestamp'].dt.date
        df_attacks['day_of_week'] = df_attacks['timestamp'].dt.day_name()
        df_attacks['confidence_level'] = pd.to_numeric(df_attacks['confidence_level'], errors='coerce').fillna(0)
    
    if not df_sessions.empty:
        df_sessions['timestamp'] = pd.to_datetime(df_sessions['timestamp'])
        df_sessions['hour'] = df_sessions['timestamp'].dt.hour
        df_sessions['date'] = df_sessions['timestamp'].dt.date
        df_sessions['day_of_week'] = df_sessions['timestamp'].dt.day_name()
        df_sessions['duration'] = pd.to_numeric(df_sessions['duration'], errors='coerce').fillna(0)
    
    return df_attacks, df_sessions

# Initial data load
df_attacks, df_sessions = load_data()

# Calculate statistics
def calculate_stats(df_attacks, df_sessions):
    stats = {}
    
    # Attack statistics
    if not df_attacks.empty:
        attack_counts = df_attacks['attack_type'].value_counts().reset_index()
        attack_counts.columns = ['Attack Type', 'Count']
        
        hourly_attacks = df_attacks.groupby('hour').size().reset_index(name='Count')
        
        threat_level_counts = df_attacks['threat_level'].value_counts().reset_index()
        threat_level_counts.columns = ['Threat Level', 'Count']
        
        browser_counts = df_attacks['browser'].value_counts().reset_index()
        browser_counts.columns = ['Browser', 'Count']
        
        stats['attack_counts'] = attack_counts
        stats['hourly_attacks'] = hourly_attacks
        stats['threat_level_counts'] = threat_level_counts
        stats['browser_counts'] = browser_counts
        
        # Top attackers
        top_attackers = df_attacks['attacker_ip'].value_counts().reset_index()
        top_attackers.columns = ['IP Address', 'Count']
        stats['top_attackers'] = top_attackers.head(10)
        
        # Attack timeline (daily counts)
        attack_timeline = df_attacks.groupby('date').size().reset_index(name='Count')
        stats['attack_timeline'] = attack_timeline
        
        # Attack type over time
        attack_type_timeline = df_attacks.groupby(['date', 'attack_type']).size().reset_index(name='Count')
        stats['attack_type_timeline'] = attack_type_timeline
        
        # Recent attacks for table
        recent_attacks = df_attacks.sort_values('timestamp', ascending=False).head(50)
        stats['recent_attacks'] = recent_attacks
    
    # Session statistics
    if not df_sessions.empty:
        section_counts = df_sessions['accessed_section'].value_counts().reset_index()
        section_counts.columns = ['Section', 'Count']
        
        hourly_sessions = df_sessions.groupby('hour').size().reset_index(name='Count')
        
        duration_stats = df_sessions.groupby('accessed_section')['duration'].agg(['mean', 'max', 'min']).reset_index()
        duration_stats.columns = ['Section', 'Average Duration', 'Max Duration', 'Min Duration']
        
        stats['section_counts'] = section_counts
        stats['hourly_sessions'] = hourly_sessions
        stats['duration_stats'] = duration_stats
        
        # Recent sessions for table
        recent_sessions = df_sessions.sort_values('timestamp', ascending=False).head(50)
        stats['recent_sessions'] = recent_sessions
    
    return stats

stats = calculate_stats(df_attacks, df_sessions)

# App layout
app.layout = dbc.Container([
    dcc.Interval(id='interval-component', interval=60*1000, n_intervals=0),  # Update every minute
    dcc.Store(id='data-store', data={'df_attacks': df_attacks.to_dict('records'), 
                                    'df_sessions': df_sessions.to_dict('records')}),
    
    dbc.Row([
        dbc.Col(html.H1("Honeypot Attack Dashboard", style=HEADER_STYLE), width=12)
    ]),
    
    # Filters Row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Filters", style={'fontWeight': 'bold'}),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Label("Date Range:"),
                            dcc.DatePickerRange(
        			id='date-range',
        			min_date_allowed=df_attacks['date'].min() if not df_attacks.empty else datetime.now().date(),
        			max_date_allowed=df_attacks['date'].max() if not df_attacks.empty else datetime.now().date(),
        			start_date=df_attacks['date'].min() if not df_attacks.empty else datetime.now().date(),
        			end_date=df_attacks['date'].max() if not df_attacks.empty else datetime.now().date(),
        			display_format='YYYY-MM-DD',
        			style={'backgroundColor': '#2a2e3f', 'color': 'white'}
    				)
                        ], width=4),
                        
                        dbc.Col([
                            html.Label("Attack Type:"),
                            dcc.Dropdown(
                                id='attack-type-filter',
                                options=[{'label': 'All', 'value': 'All'}] + 
                                        [{'label': atype, 'value': atype} 
                                         for atype in df_attacks['attack_type'].unique()] if not df_attacks.empty else [],
                                value='All',
                                multi=False,
                                clearable=False,
                                style={'backgroundColor': 'white', 'color': 'black'}
                            )
                        ], width=4),
                        
                        dbc.Col([
                            html.Label("Threat Level:"),
                            dcc.Dropdown(
                                id='threat-level-filter',
                                options=[{'label': 'All', 'value': 'All'}] + 
                                        [{'label': level, 'value': level} 
                                         for level in ['Critical', 'High', 'Medium', 'Low']],
                                value='All',
                                multi=False,
                                clearable=False,
                                style={'backgroundColor': 'white', 'color': 'black'}
                            )
                        ], width=4)
                    ]),
                    
                    dbc.Row([
                        dbc.Col([
                            html.Label("IP Address:"),
                            dcc.Dropdown(
                                id='ip-filter',
                                options=[{'label': 'All', 'value': 'All'}] + 
                                        [{'label': ip, 'value': ip} 
                                         for ip in df_attacks['attacker_ip'].unique()] if not df_attacks.empty else [],
                                value='All',
                                multi=False,
                                clearable=False,
                                style={'backgroundColor': 'white', 'color': 'black'}
                            )
                        ], width=4),
                        
                        dbc.Col([
                            html.Label("Browser:"),
                            dcc.Dropdown(
                                id='browser-filter',
                                options=[{'label': 'All', 'value': 'All'}] + 
                                        [{'label': browser, 'value': browser} 
                                         for browser in df_attacks['browser'].unique()] if not df_attacks.empty else [],
                                value='All',
                                multi=False,
                                clearable=False,
                                style={'backgroundColor': 'white', 'color': 'black'}
                            )
                        ], width=4),
                        
                        dbc.Col([
                            html.Label("SQLi Possibility:"),
                            dcc.Dropdown(
                                id='sqli-filter',
                                options=[{'label': 'All', 'value': 'All'}] + 
                                        [{'label': sqli, 'value': sqli} 
                                         for sqli in ['High', 'Medium', 'Low', 'Unknown']],
                                value='All',
                                multi=False,
                                clearable=False,
                                style={'backgroundColor': 'white', 'color': 'black'}
                            )
                        ], width=4)
                    ], className="mt-3")
                ])
            ], style=CARD_STYLE)
        ], width=12)
    ], className="mb-4"),
    
    # Summary Cards Row
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardHeader("Total Attacks", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                html.H4(f"{len(df_attacks)}", className="card-title", style={'color': '#ff6b6b'}),
                html.Div(id='attack-change-indicator', className="mt-2")
            ])
        ], style=CARD_STYLE), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Attack Types", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                html.H4(f"{len(df_attacks['attack_type'].unique()) if not df_attacks.empty else 0}", 
                       className="card-title", style={'color': '#4ecdc4'})
            ])
        ], style=CARD_STYLE), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Sections Accessed", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                html.H4(f"{len(df_sessions['accessed_section'].unique()) if not df_sessions.empty else 0}", 
                       className="card-title", style={'color': '#ffe66d'})
            ])
        ], style=CARD_STYLE), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Unique Attackers", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                html.H4(f"{len(df_attacks['attacker_ip'].unique()) if not df_attacks.empty else 0}", 
                       className="card-title", style={'color': '#ff9ff3'})
            ])
        ], style=CARD_STYLE), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Critical Threats", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                html.H4(f"{len(df_attacks[df_attacks['threat_level'] == 'Critical']) if not df_attacks.empty else 0}", 
                       className="card-title", style={'color': '#ff7675'})
            ])
        ], style=CARD_STYLE), width=2),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Avg. Session Duration", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                html.H4(f"{df_sessions['duration'].mean():.2f}s" if not df_sessions.empty else '0s', 
                       className="card-title", style={'color': '#74b9ff'})
            ])
        ], style=CARD_STYLE), width=2)
    ], className="mb-4"),
    
    # First Row of Charts
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardHeader("Attack Types Distribution", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dcc.Graph(id='attack-types-pie')
            ])
        ], style=CARD_STYLE), width=4),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Threat Level Distribution", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dcc.Graph(id='threat-level-pie')
            ])
        ], style=CARD_STYLE), width=4),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Top Attackers", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dcc.Graph(id='top-attackers-bar')
            ])
        ], style=CARD_STYLE), width=4)
    ], className="mb-4"),
    
    # Second Row of Charts
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardHeader("Hourly Attack Pattern", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dcc.Graph(id='hourly-attacks')
            ])
        ], style=CARD_STYLE), width=6),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Browser Distribution", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dcc.Graph(id='browser-distribution')
            ])
        ], style=CARD_STYLE), width=6)
    ], className="mb-4"),
    
    # Third Row of Charts
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardHeader("Top Accessed Sections", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dcc.Graph(id='section-access-bar')
            ])
        ], style=CARD_STYLE), width=6),
        
        dbc.Col(dbc.Card([
            dbc.CardHeader("Session Duration by Section", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dcc.Graph(id='duration-stats')
            ])
        ], style=CARD_STYLE), width=6)
    ], className="mb-4"),
    
    # Attack Details Table
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardHeader("Recent Attack Details", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dash_table.DataTable(
                    id='attack-table',
                    columns=[
                        {"name": "Timestamp", "id": "timestamp", "type": "datetime"},
                        {"name": "IP", "id": "attacker_ip"},
                        {"name": "Attack Type", "id": "attack_type"},
                        {"name": "Threat Level", "id": "threat_level"},
                        {"name": "Username", "id": "username"},
                        {"name": "Confidence", "id": "confidence_level", "type": "numeric"},
                        {"name": "SQLi Possibility", "id": "sqli_possibility"},
                        {"name": "Browser", "id": "browser"},
                        {"name": "Action Taken", "id": "action_taken"}
                    ],
                    style_table={'overflowX': 'auto'},
                    style_header={
                        'backgroundColor': '#2a2e3f',
                        'color': 'white',
                        'fontWeight': 'bold'
                    },
                    style_cell={
                        'backgroundColor': '#1e2130',
                        'color': 'white',
                        'border': '1px solid #2a2e3f',
                        'whiteSpace': 'normal',
                        'height': 'auto'
                    },
                    style_data_conditional=[
                        {
                            'if': {'filter_query': '{attack_type} = "SQL Injection"', 'column_id': 'attack_type'},
                            'backgroundColor': '#ff6b6b', 'color': 'white'
                        },
                        {
                            'if': {'filter_query': '{attack_type} = "Zero-Day Anomaly"', 'column_id': 'attack_type'},
                            'backgroundColor': '#4ecdc4', 'color': 'white'
                        },
                        {
                            'if': {'filter_query': '{threat_level} = "Critical"', 'column_id': 'threat_level'},
                            'backgroundColor': '#ff0000', 'color': 'white', 'fontWeight': 'bold'
                        },
                        {
                            'if': {'filter_query': '{threat_level} = "High"', 'column_id': 'threat_level'},
                            'backgroundColor': '#ff6347', 'color': 'white'
                        },
                        {
                            'if': {'column_id': 'confidence_level', 'filter_query': '{confidence_level} > 0.8'},
                            'backgroundColor': '#ff0000', 'color': 'white', 'fontWeight': 'bold'
                        }
                    ],
                    page_size=10,
                    filter_action="native",
                    sort_action="native",
                    sort_mode="multi",
                    tooltip_data=[
                        {
                            column: {'value': str(value), 'type': 'markdown'}
                            for column, value in row.items()
                        } for row in df_attacks.to_dict('records')
                    ],
                    tooltip_duration=None
                )
            ])
        ], style=CARD_STYLE), width=12)
    ], className="mb-4"),
    
    # Session Details Table
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardHeader("Recent Session Details", style={'fontWeight': 'bold'}),
            dbc.CardBody([
                dash_table.DataTable(
                    id='session-table',
                    columns=[
                        {"name": "Timestamp", "id": "timestamp", "type": "datetime"},
                        {"name": "IP", "id": "attacker_ip"},
                        {"name": "Username", "id": "username"},
                        {"name": "Accessed Section", "id": "accessed_section"},
                        {"name": "Duration (s)", "id": "duration", "type": "numeric"},
                        {"name": "Data Type", "id": "data_type"},
                        {"name": "Browser", "id": "user_agent"}
                    ],
                    style_table={'overflowX': 'auto'},
                    style_header={
                        'backgroundColor': '#2a2e3f',
                        'color': 'white',
                        'fontWeight': 'bold'
                    },
                    style_cell={
                        'backgroundColor': '#1e2130',
                        'color': 'white',
                        'border': '1px solid #2a2e3f',
                        'whiteSpace': 'normal',
                        'height': 'auto'
                    },
                    style_data_conditional=[
                        {
                            'if': {'filter_query': '{accessed_section} = "Admin Credentials"', 'column_id': 'accessed_section'},
                            'backgroundColor': '#ff6b6b', 'color': 'white'
                        },
                        {
                            'if': {'filter_query': '{duration} > 10', 'column_id': 'duration'},
                            'backgroundColor': '#4ecdc4', 'color': 'white'
                        }
                    ],
                    page_size=10,
                    filter_action="native",
                    sort_action="native",
                    sort_mode="multi",
                    tooltip_data=[
                        {
                            column: {'value': str(value), 'type': 'markdown'}
                            for column, value in row.items()
                        } for row in df_sessions.to_dict('records')
                    ],
                    tooltip_duration=None
                )
            ])
        ], style=CARD_STYLE), width=12)
    ], className="mb-4"),
    
    # Footer
    dbc.Row([
        dbc.Col(html.Div([
            html.P("Honeypot Security Dashboard", style={'textAlign': 'center', 'color': '#aaaaaa'}),
            html.P(id='last-updated', style={'textAlign': 'center', 'color': '#aaaaaa', 'fontSize': '12px'})
        ]), width=12)
    ])
], fluid=True)

# Callback to update data
@app.callback(
    [Output('data-store', 'data'),
     Output('last-updated', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_data(n):
    df_attacks, df_sessions = load_data()
    last_updated = f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    return {'df_attacks': df_attacks.to_dict('records'), 'df_sessions': df_sessions.to_dict('records')}, last_updated

# Callback to update attack change indicator
@app.callback(
    Output('attack-change-indicator', 'children'),
    [Input('data-store', 'data')],
    [State('data-store', 'data')]
)
def update_attack_indicator(new_data, old_data):
    if not old_data or 'df_attacks' not in old_data:
        return ""
    
    old_count = len(old_data['df_attacks']) if 'df_attacks' in old_data else 0
    new_count = len(new_data['df_attacks'])
    
    if new_count > old_count:
        return html.Div([
            html.I(className="fas fa-arrow-up text-danger mr-1"),
            f" +{new_count - old_count} new attacks"
        ], className="text-danger")
    elif new_count < old_count:
        return html.Div([
            html.I(className="fas fa-arrow-down text-success mr-1"),
            f" -{old_count - new_count} attacks"
        ], className="text-success")
    else:
        return html.Div([
            html.I(className="fas fa-equals text-muted mr-1"),
            " No change"
        ], className="text-muted")

# Callback to filter data based on inputs
@app.callback(
    [Output('attack-types-pie', 'figure'),
     Output('threat-level-pie', 'figure'),
     Output('top-attackers-bar', 'figure'),
     Output('hourly-attacks', 'figure'),
     Output('section-access-bar', 'figure'),
     Output('duration-stats', 'figure'),
     Output('browser-distribution', 'figure'),
     Output('attack-table', 'data'),
     Output('session-table', 'data')],
    [Input('data-store', 'data'),
     Input('date-range', 'start_date'),
     Input('date-range', 'end_date'),
     Input('attack-type-filter', 'value'),
     Input('threat-level-filter', 'value'),
     Input('ip-filter', 'value'),
     Input('browser-filter', 'value'),
     Input('sqli-filter', 'value')]
)
def update_dashboard(data, start_date, end_date, attack_type, threat_level, ip, browser, sqli):
    # Convert data back to DataFrames
    df_attacks = pd.DataFrame(data['df_attacks'])
    df_sessions = pd.DataFrame(data['df_sessions'])
    
    # Convert timestamps
    if not df_attacks.empty:
        df_attacks['timestamp'] = pd.to_datetime(df_attacks['timestamp'])
        df_attacks['date'] = df_attacks['timestamp'].dt.date
    if not df_sessions.empty:
        df_sessions['timestamp'] = pd.to_datetime(df_sessions['timestamp'])
        df_sessions['date'] = df_sessions['timestamp'].dt.date
    
    # Apply filters
    if not df_attacks.empty:
        # Date filter
        if start_date and end_date:
            start_date = pd.to_datetime(start_date).date()
            end_date = pd.to_datetime(end_date).date()
            df_attacks = df_attacks[(df_attacks['date'] >= start_date) & (df_attacks['date'] <= end_date)]
        
        # Attack type filter
        if attack_type != 'All':
            df_attacks = df_attacks[df_attacks['attack_type'] == attack_type]
        
        # Threat level filter
        if threat_level != 'All':
            df_attacks = df_attacks[df_attacks['threat_level'] == threat_level]
        
        # IP filter
        if ip != 'All':
            df_attacks = df_attacks[df_attacks['attacker_ip'] == ip]
        
        # Browser filter
        if browser != 'All':
            df_attacks = df_attacks[df_attacks['browser'] == browser]
        
        # SQLi filter
        if sqli != 'All':
            df_attacks = df_attacks[df_attacks['sqli_possibility'] == sqli]
    
    if not df_sessions.empty:
        # Date filter for sessions
        if start_date and end_date:
            df_sessions = df_sessions[(df_sessions['date'] >= start_date) & (df_sessions['date'] <= end_date)]
        
        # Filter sessions based on filtered attacks IPs
        if ip != 'All':
            df_sessions = df_sessions[df_sessions['attacker_ip'] == ip]
    
    # Recalculate statistics with filtered data
    stats = calculate_stats(df_attacks, df_sessions)
    
    # Create figures
    figures = []
    
    # Attack Types Pie Chart
    attack_types_fig = px.pie(
        stats.get('attack_counts', pd.DataFrame(columns=['Attack Type', 'Count'])),
        values='Count',
        names='Attack Type',
        hole=0.4,
        color_discrete_sequence=px.colors.qualitative.Pastel,
        title='Attack Types Distribution'
    ).update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        title_x=0.5
    )
    figures.append(attack_types_fig)
    
    # Threat Level Pie Chart
    threat_level_fig = px.pie(
        stats.get('threat_level_counts', pd.DataFrame(columns=['Threat Level', 'Count'])),
        values='Count',
        names='Threat Level',
        hole=0.3,
        color_discrete_sequence=px.colors.sequential.Reds,
        title='Threat Level Distribution'
    ).update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        title_x=0.5
    )
    figures.append(threat_level_fig)
    
    # Top Attackers Bar Chart
    top_attackers_fig = px.bar(
        stats.get('top_attackers', pd.DataFrame(columns=['IP Address', 'Count'])),
        x='IP Address',
        y='Count',
        color='Count',
        color_continuous_scale='thermal',
        title='Top Attackers (IPs)'
    ).update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        xaxis_title="IP Address",
        yaxis_title="Attack Count",
        title_x=0.5
    )
    figures.append(top_attackers_fig)
    
    # Hourly Attacks
    hourly_attacks_fig = px.bar(
        stats.get('hourly_attacks', pd.DataFrame(columns=['hour', 'Count'])),
        x='hour',
        y='Count',
        color='Count',
        color_continuous_scale='magma',
        title='Hourly Attack Pattern'
    ).update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        xaxis_title="Hour of Day",
        yaxis_title="Attack Count",
        title_x=0.5
    )
    figures.append(hourly_attacks_fig)
    
    # Section Access Bar Chart
    section_access_fig = px.bar(
        stats.get('section_counts', pd.DataFrame(columns=['Section', 'Count'])),
        x='Section',
        y='Count',
        color='Section',
        color_discrete_sequence=px.colors.qualitative.Pastel,
        title='Top Accessed Sections'
    ).update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        xaxis_title="Section",
        yaxis_title="Access Count",
        title_x=0.5
    )
    figures.append(section_access_fig)
    
    # Duration Stats
    duration_stats_fig = px.bar(
        stats.get('duration_stats', pd.DataFrame(columns=['Section', 'Average Duration'])),
        x='Section',
        y='Average Duration',
        color='Average Duration',
        color_continuous_scale='viridis',
        title='Average Session Duration by Section'
    ).update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        xaxis_title="Section",
        yaxis_title="Average Duration (seconds)",
        title_x=0.5
    )
    figures.append(duration_stats_fig)
    
    # Browser Distribution
    browser_fig = px.pie(
        stats.get('browser_counts', pd.DataFrame(columns=['Browser', 'Count'])),
        values='Count',
        names='Browser',
        hole=0.3,
        color_discrete_sequence=px.colors.qualitative.Pastel,
        title='Browser Distribution'
    ).update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        title_x=0.5
    )
    figures.append(browser_fig)
    
    # Prepare table data
    attack_table_data = df_attacks.sort_values('timestamp', ascending=False).head(50).to_dict('records') if not df_attacks.empty else []
    session_table_data = df_sessions.sort_values('timestamp', ascending=False).head(50).to_dict('records') if not df_sessions.empty else []
    
    return tuple(figures + [attack_table_data, session_table_data])

if __name__ == '__main__':
    app.run(debug=True, port=8050)
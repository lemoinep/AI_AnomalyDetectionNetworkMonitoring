# Author(s): Dr. Patrick Lemoine
# Visualization of results. 
# There is still work to do to offer a better design for the skill. 
# Can be added a map of the earth to see the connections ? I'll see.


import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("network_ai_report.csv")

print(df.head())

plt.figure(figsize=(10,6))
df['process'].value_counts().plot(kind='bar')
plt.title("Number of Connections per Process")
plt.xlabel("Process Name")
plt.ylabel("Number of Connections")
plt.tight_layout()
plt.show()


if 'AI_ALERT' in df.columns and 'timestamp' in df.columns:
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    ai_alerts = df[df['AI_ALERT'] == 'YES']
    alerts_per_minute = ai_alerts.groupby(pd.Grouper(key='timestamp', freq='1min')).size()
    alerts_per_minute.plot(kind='line', marker='o')
    plt.title("AI Alerts Over Time")
    plt.xlabel("Time")
    plt.ylabel("Number of AI Alerts per Minute")
    plt.tight_layout()
    plt.show()


plt.figure(figsize=(10,6))
df['raddr_port'] = df['raddr'].apply(lambda x: x.split(":")[1] if pd.notnull(x) and ":" in x else None)
df['raddr_port'].value_counts().head(20).plot(kind='bar')
plt.title("Top 20 Remote Ports")
plt.xlabel("Remote Port")
plt.ylabel("Number of Connections")
plt.tight_layout()
plt.show()



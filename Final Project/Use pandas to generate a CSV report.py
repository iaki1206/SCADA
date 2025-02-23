import pandas as pd
df = pd.read_sql('SELECT * FROM events', conn)
df.to_csv('security_report.csv', index=False)
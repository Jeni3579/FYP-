import pandas as pd
import random

print("Generating simulated security event log...")
event_types = {
    'Unauthorized Access': ['Failed Login', 'Failed Login', 'Successful Login (Unusual Hour)'],
    'Ransomware Activity': ['Multiple Files Renamed', 'File Encrypted', 'Shadow Copy Deleted'],
    'Potential Malware': ['Suspicious Process Created', 'Registry Key Modified', 'Connection to Known C2 Server'],
    'Normal': ['File Accessed', 'User Login', 'User Logout', 'File Created', 'Process Started']
}
log_data = []
for i in range(1000):
    category = random.choices(list(event_types.keys()), weights=[10, 5, 5, 80], k=1)[0]
    event = random.choice(event_types[category])
    log_data.append({
        'user': f'user{random.randint(1, 50)}',
        'event_type': event,
        'threat_category': category
    })
df = pd.DataFrame(log_data)
df.to_csv('security_events.csv', index=False)
print("Successfully generated 'security_events.csv'.")
from zapv2 import ZAPv2
import time

# ZAP API COnfiguration
API_KEY = '' # If using API key, insert it here
ZAP_ADDRESS = 'http://localhost'
ZAP_PORT = '8080'
TARGET = 'http://juice-shop:3000'

zap = ZAPv2(apikey=API_KEY, proxies={'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}', 'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'})

# Access target
print(f'Accessing target {TARGET}')
zap.urlopen(TARGET)
time.sleep(2)  # Wait for the site to load

# Spidering
print('Spidering target...')
scan_id = zap.spider.scan(TARGET)
while int(zap.spdier.status(scan_id)) < 100:
    print(f'Spider progress: {zap.spider.status(scan_id)}%')
    time.sleep(1) # Wait for spider to finish

# Actice scan
print('Active scanning target...')
ascan_id = zap.ascan.scan(TARGET)
while int(zap.ascan.status(ascan_id)) < 100:
    print(f'Scan progress: {zap.ascan.status(ascan_id)}%')
    time.sleep(5)

# Alerts
alerts = zap.core.alerts()
print(f'Found {len(alerts)} alerts')

# Write to file
with open('reports/zap_report.txt', 'w') as f:
    for alert in alerts:
        f.write(str(alert) + '\n')
print('ZAP scanning complete.')
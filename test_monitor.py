import psutil
import time

print("Testing psutil CPU readings...")
for i in range(5):
    cpu = psutil.cpu_percent(interval=1)
    print(f"Reading {i+1}: {cpu}%")

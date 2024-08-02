#!/usr/bin/env python3

import os
import sys
import subprocess

# Get the file path from command line argument
if len(sys.argv) < 2:
  print("Usage: python script.py <execute> <file_path>")
  sys.exit(1)

# Input the file path where the data is located
execute = sys.argv[1]
file_path = sys.argv[2]

# Convert relative path to absolute path
execute = os.path.abspath(execute)
file_path = os.path.abspath(file_path)

row = 16
iter = 3
for thread in [1, 2, 4, 8, 16, 20, 24, 28, 32]:
  # Run the TPC-H benchmark
  print(f"Running TPC-H benchmark with {thread} threads")
  subprocess.run([execute, str(row), str(thread), str(iter)],
                  stdout=open(file_path, "a"),
                  stderr=subprocess.DEVNULL)

average_query_times = {}
with open(file_path, "r") as file:
  data = file.read()
  import re
  # Overall Query Time [thread xxx]: xxx ms
  query_times = re.findall(r'Overall Query Time \[thread (\d+)\]: ([\d.]+) ms', data)
  query_times = [(int(query_time[0]), float(query_time[1])) for query_time in query_times]
  query_times.sort(key=lambda x: x[0])
  # average query time, if multiple iterations (query_time[0] is same)
  for thread, time in query_times:
    if thread not in average_query_times:
      average_query_times[thread] = []
    average_query_times[thread].append(time)
  
  for thread, times in average_query_times.items():
    avg_time = sum(times) / len(times)
    average_query_times[thread] = avg_time

# Print the average query time for each thread
for thread, avg_time in average_query_times.items():
  # throughput and latency
  throughput = thread / avg_time * 1000
  latency = avg_time
  print(f"Thread {thread}: {throughput:.2f} queries/s, {latency:.2f} ms")
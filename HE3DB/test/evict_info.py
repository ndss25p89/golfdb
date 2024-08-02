#!/usr/bin/env python3
import os
import sys

# Get the file path from command line argument
if len(sys.argv) < 2:
  print("Usage: python script.py <file_path>")
  sys.exit(1)

# Input the file path where the data is located
file_path = sys.argv[1]

# Convert relative path to absolute path
file_path = os.path.abspath(file_path)

lru_evict_counts_list = []

with open(file_path, "r") as file:
  data = file.read()
  import re
  group_matches = re.findall(r'(?s)===== Query Evaluation:(.*?)\[Evaluation\] (\d+\.\d+|$)', data)
  
  for group_match in group_matches:
    evicts = re.findall(r'(lru|dbe) evict: (\d+)', group_match[0])
    evict_counts = [int(evict[1]) for evict in evicts]
    lru_evict_counts_list.append(evict_counts)

# Print the number of evictions for each query
for i, evict_counts in enumerate(lru_evict_counts_list):
  print(f"Query {i+1}: {len(evict_counts)}")
#!/bin/bash

read -p "Enter the directory path containing the programs: " program_dir

if [ ! -d "$program_dir" ]; then
  echo "Error: $program_dir does not exist."
  exit 1
fi

programs=(
  "tpch_q1"
  "tpch_q4"
  "tpch_q6"
)

for program in "${programs[@]}"; do
  program_path="$program_dir/$program"
  echo "Running program: $program_path"
  "$program_path"
done

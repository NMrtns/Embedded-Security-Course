#!/bin/bash

# Function to handle termination signals
term_handler() {
  echo "Received termination signal. Exiting..."
  exit 0
}

# Trap termination signals
trap 'term_handler' INT TERM

#run generate hashed users
/app/generate_hashed_users
cat /app/hashed_users.txt

while true; do
#  gdb -ex "run" -ex "quit" -ex "bt" --args /app/login
  /app/login
done
#!/bin/bash

# Function to handle termination signals
term_handler() {
  echo "Received termination signal. Exiting..."
  exit 0
}

# Trap termination signals
trap 'term_handler' INT TERM

/app/generate_hashed_users
cat /app/hashed_users.txt

while true; do
  /app/login
done
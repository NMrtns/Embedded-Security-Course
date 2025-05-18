# Use the official GCC image from the Docker Hub
FROM gcc:latest

# Install build essentials, and legacy services
RUN apt-get update && \
    apt-get install -y build-essential net-tools nmap \
#    telnetd ftpd rsh-server net-tools nmap xinetd
    openbsd-inetd telnetd proftpd rsh-server inetutils-ping telnet \
    && apt-get purge -y inet-superserver \
    && apt-get install -y xinetd


# Set the working directory inside the container
WORKDIR /app

# Copy the C program to the working directory
COPY login.c /app/
COPY users.txt /app/
COPY start.sh /app/

# Compile the C program
RUN gcc /app/login.c -o /app/login

# Configure services
RUN echo "ALL: ALL" >> /etc/hosts.allow && \
    echo "ALL: ALL" >> /etc/hosts.deny

# Make start.sh executable
RUN chmod +x /app/start.sh

# Specify the command to run the program
CMD ["/bin/bash", "/app/start.sh"]
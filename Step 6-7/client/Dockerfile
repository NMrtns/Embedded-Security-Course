FROM gcc:latest
RUN apt-get update && apt-get install -y libssl-dev net-tools iputils-ping telnet
WORKDIR /app
COPY . .
RUN gcc -o client client.c -lssl -lcrypto

#CMD ["./client"]
CMD ["/bin/bash"]
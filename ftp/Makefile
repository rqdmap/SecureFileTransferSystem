all: client server 

client: client.cpp ftp.h ftp.cpp rqdmap.h
	g++ -o client client.cpp ftp.h ftp.cpp rqdmap.h
server: server.cpp ftp.h ftp.cpp rqdmap.h
	g++ -o server server.cpp ftp.h ftp.cpp rqdmap.h

clean:
	rm client server
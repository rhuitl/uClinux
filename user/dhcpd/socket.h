/* socket.h */

int serverSocket(short listen_port, char *interface_name);
int clientSocket(short send_from_port, short send_to_port, char *interface_name);


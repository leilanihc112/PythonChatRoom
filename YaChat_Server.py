import socket
import threading
import argparse

clients_list = []
semaphore_clients_list = threading.Semaphore(1)

def serve(id, sock_tcp, sock_udp):

    RJCT_FLAG = False

    while True:
        helo_message = ''
        try:
            while "\n" not in helo_message:
                chunk = sock_tcp.recv(2048).decode()
                helo_message = helo_message+chunk
        except ConnectionResetError:
            return
        if "HELO " not in helo_message:
            print("Unexpected message")
            continue
        helo_message = helo_message.replace("HELO ","")
        helo_message = helo_message.replace("\n","")
        for x in clients_list:
            if helo_message.split(" ")[0] in x:
                print("got here")
                rjct_message = "RJCT " + helo_message.split(" ")[0] + "\n"
                sock_tcp.send(rjct_message.encode())
                RJCT_FLAG = True
                break
        if RJCT_FLAG == True:
            break
        else:
            semaphore_clients_list.acquire()
            clients_list.insert(0, helo_message)
            acpt_message = "ACPT "
            for x in clients_list:
                acpt_message = acpt_message + x + ":"
            acpt_message = acpt_message[:-1] + "\n"
            sock_tcp.send(acpt_message.encode())
            if len(clients_list) > 1:
                for x in range(1, len(clients_list)):
                    join_message = "JOIN " + helo_message + "\n"
                    sock_udp.sendto(join_message.encode(), (clients_list[x].split(" ")[1], int(clients_list[x].split(" ")[2])))
            semaphore_clients_list.release()
            break

    while True:
        exit_message = ''
        try:
            while "\n" not in exit_message:
                chunk = sock_tcp.recv(2048).decode()
                exit_message = exit_message+chunk
        except ConnectionResetError:
            return
        if "EXIT\n" not in exit_message:
            print("Unexpected message")
            continue
        else:
            semaphore_clients_list.acquire()
            for x in range(0, len(clients_list)):
                exit_send_message = "EXIT " + helo_message.split(" ")[0] + "\n"
                sock_udp.sendto(exit_send_message.encode(), (clients_list[x].split(" ")[1], int(clients_list[x].split(" ")[2])))
        clients_list.remove(helo_message)
        semaphore_clients_list.release()
        break
                
    sock_tcp.close()


def main(port):

    # create an INET, STREAMing socket
    serversockettcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversockettcp.bind(("127.0.0.1", port))
    serversockettcp.listen(5)
    sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # get local ip
    local_ip = socket.gethostbyname(socket.gethostname())
    #sock_udp.setblocking(False)
    sock_udp.bind((local_ip, 0))
    # create an INET, DGRAMing socket
    id=0
    while True:
        # accept connections
        (clientsockettcp, address) = serversockettcp.accept()
        t = threading.Thread(target=serve, args=(id,clientsockettcp,sock_udp))
        t.start()
        id=id+1


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('server_port', help='Port of chat server')

    args = parser.parse_args()

    main(int(args.server_port))

import socket
import argparse
import threading
import os
import sys
import tkinter as tk

screen_names_list = []
gl_messages = None
screen_names_listbox = None
window = tk.Tk()

class acpt_msgs(threading.Thread):
    
    def __init__(self, sock_udp, sock_tcp, screen_name):
        super().__init__()
        self.sock_udp = sock_udp
        self.sock_tcp = sock_tcp
        self.screen_name = screen_name

    def run(self):
        global screen_names_list
        global screen_names_listbox
        global gl_messages

        while True:
            message_b, ip_and_port = self.sock_udp.recvfrom(4096)
            message = message_b.decode()
            if "MESG" in message:
                message = message.replace("MESG ", "").replace("\n", "")
                gl_messages.insert(tk.END, message)
            elif "JOIN" in message:
                message_print = message.split(" ")
                if self.screen_name not in message:
                    gl_messages.insert(tk.END, "\n")
                    gl_messages.insert(tk.END, "SERVER: "+message_print[1].replace("\n","")+" has entered the chatroom")
                    gl_messages.insert(tk.END, "\n")
                    message = message.replace("JOIN ", "").replace("\n", "")
                    screen_names_list.append(message)
                    screen_names_listbox.insert(tk.END, message_print[1].replace("\n",""))
            elif "EXIT" in message:
                message_print = message.split(" ")
                if self.screen_name in message:
                    self.exit()
                gl_messages.insert(tk.END, "\n")
                gl_messages.insert(tk.END, "SERVER: "+message_print[1].replace("\n","")+" has left the chatroom")
                gl_messages.insert(tk.END, "\n")
                for i in screen_names_list:
                    if message_print[1].replace("\n","") in i:
                        screen_names_list.remove(i)
                        idx = screen_names_listbox.get(0, tk.END).index(message_print[1].replace("\n",""))
                        screen_names_listbox.delete(idx)
                        break

    def exit(self):
        # exit message
        gl_messages.insert(tk.END, "SERVER: Good Bye!")
        self.sock_tcp.close()
        self.sock_udp.close()
        os._exit(1)

class Client:

    def __init__(self, host, port, screen_name):
        self.host = host
        self.port = port
        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.screen_name = screen_name


    def start(self):
        global screen_names_list
        global screen_names_listbox

        # get local ip
        local_ip = socket.gethostbyname(socket.gethostname())
        #sock_udp.setblocking(False)
        self.sock_udp.bind((local_ip, 0))
        # local ip and udp port
        local_ip, udp_port = self.sock_udp.getsockname()
        try:
            # connect to the server
            self.sock_tcp.connect((self.host, self.port))
        except ConnectionRefusedError:
            print("Could not connect to server")
            os._exit(0)
        # send message as first greeting
        helo_msg = "HELO "+self.screen_name+" "+str(local_ip)+" "+str(udp_port)+"\n"
        try:
            self.sock_tcp.send(helo_msg.encode())
            # accept or reject message
            acptrjctmessage = ''
            while "\n" not in acptrjctmessage:
                chunk = self.sock_tcp.recv(2048).decode()
                acptrjctmessage = acptrjctmessage+chunk
            if "RJCT" in acptrjctmessage:
                print("Screen name already taken")
                self.sock_tcp.close()
                self.sock_udp.close()
                os._exit(0)
            elif "ACPT" in acptrjctmessage:
                # parse accept to see everyone currently in the chatroom
                acptrjctmessage = acptrjctmessage.replace("ACPT ","")
                acptrjctmessage = acptrjctmessage.replace("\n","")
                screen_names_list = acptrjctmessage.split(':')
            else:
                print("Unexpected message")
                self.sock_tcp.close()
                self.sock_udp.close()
                os._exit(0)
        except ConnectionResetError:
            print("Connection from server lost")
            os._exit(1)

        receive = acpt_msgs(self.sock_udp, self.sock_tcp, self.screen_name)
        receive.start()

        return receive


    def send_msgs(self, text_input):
        global gl_messages

        msg = text_input.get()
        text_input.delete(0, tk.END)
        gl_messages.insert(tk.END, self.screen_name + ": " + msg)

        try: 
            if msg == "QUIT":
                self.on_exit()
            else:
                udp_msg = "MESG "+self.screen_name+": "+msg+"\n"
                for i in screen_names_list:
                    if self.screen_name not in i:
                        temp = i.split(" ")
                        self.sock_udp.sendto(udp_msg.encode(), (temp[1], int(temp[2])))
        except ConnectionResetError:
            print("Connection from server lost")
            os._exit(1)


    def on_exit(self):
        try: 
            # exit message
            self.sock_tcp.send("EXIT\n".encode())
        except ConnectionResetError:
            print("Connection from server lost")
            os._exit(1)

    
def main(host, port, screen_name):

    global gl_messages
    global screen_names_listbox
    global window 

    window.title("Chatroom")

    frm_messages = tk.Frame(master=window)
    frm_chatroom = tk.Frame(master=window)
    scrollbar = tk.Scrollbar(master=frm_messages)
    scrollbar2 = tk.Scrollbar(master=frm_chatroom)
    messages = tk.Listbox(
        master=frm_messages,
        yscrollcommand = scrollbar.set
    )
    chatroom_names = tk.Listbox(
        master=frm_chatroom,
        yscrollcommand = scrollbar2.set
    )
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
    scrollbar2.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
    chatroom_names.pack(side=tk.RIGHT, fill=tk.Y, expand=True)
    messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    client = Client(host, port, screen_name)
    receive = client.start()

    messages.insert(tk.END, "Welcome, "+screen_name+"!\n You can start sending messages now. Type \'QUIT\' at any time to exit.")
    messages.insert(tk.END, "\n")

    chatroom_names.insert(tk.END, "Online:")
    chatroom_names.insert(tk.END, "\n")
    for i in screen_names_list:
        temp = i.split(" ")
        chatroom_names.insert(tk.END, temp[0])

    gl_messages = messages
    screen_names_listbox = chatroom_names

    frm_messages.grid(row=0, column=0, columnspan=2, sticky="nsew")
    frm_chatroom.grid(row=0, column=2, columnspan=1, sticky="nsew")

    frm_entry = tk.Frame(master=window)
    text_input = tk.Entry(master=frm_entry)
    text_input.pack(fill=tk.BOTH, expand=True)
    text_input.bind("<Return>", lambda x: client.send_msgs(text_input))

    btn_send = tk.Button(
        master=window,
        text='Send',
        command=lambda: client.send_msgs(text_input)
    )

    btn_exit = tk.Button(
        master=window,
        text='EXIT',
        command=lambda: client.on_exit()
    )

    frm_entry.grid(row=1, column=0, padx=10, sticky="ew")
    btn_send.grid(row=1, column=1, pady=10, sticky="ew")
    btn_exit.grid(row=2, column=0, pady=10, sticky="ew")

    window.rowconfigure(0, minsize=500, weight=1)
    window.rowconfigure(1, minsize=50, weight=0)
    window.columnconfigure(0, minsize=500, weight=1)
    window.columnconfigure(1, minsize=200, weight=0)

    window.protocol("WM_DELETE_WINDOW", client.on_exit)
    window.mainloop()


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('screen_name', help='Screen name of chat user')
    parser.add_argument('server_hostname', help='Hostname of chat server')
    parser.add_argument('server_port', help='Port of chat server')

    args = parser.parse_args()

    main(args.server_hostname, int(args.server_port), args.screen_name)

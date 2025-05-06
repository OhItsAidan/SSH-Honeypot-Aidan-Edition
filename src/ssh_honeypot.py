#!/usr/bin/env python3
import argparse
import threading
import socket
import sys
import os
import traceback
import logging
import paramiko
from datetime import datetime
from binascii import hexlify

HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

UP_KEY = '\xb1[A'.encode()
DOWN_KEY = '\xb1[B'.encode()
RIGHT_KEY = '\xb1[C'.encode()
LEFT_KEY = '\xb1[D'.encode()
BACK_KEY = '\x7f'.encode()

logging.basicConfig(
 format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
 level=logging.INFO,
filename='ssh_honeypot.log')




class SshHoneypot(paramiko.ServerInterface):

    client_ip = None
    username = None

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.cwd = '/'
        self.files = {
            "/": {
                "bin": {},
                "etc": {
                    "blackwall": {
                        "blackwall.logs": (
                            "## [INITIATE LOG STREAM]\r\n"
                            "2025-04-25T03:22:14Z :: PROTOCOL BREACH // SOURCE: UNKNOWN\r\n"
                            "2025-04-25T03:22:27Z :: '\u2588\u2588\u2588\u2588 INTERFERENCE DETECTED\r\n"
                            "2025-04-25T03:22:50Z :: SUBJECT ID: 'JAMIE' MADE CONTACT\r\n"
                            "...\r\n"
                            "IT'S INSIDE\r\n"
                            "2025-04-25TO3:23:04Z :: [FEEDBACK LOOP BEGUN]\r\n"
                            ">>>> SYSTEM MEMORY BURNING\r\n"
                            ">>>> RUN[echo \"We see you.\"]\r\n"
                            ">>>> [SIGNAL LOST]\r\n"
                        ),
                        "logic.txt": (
                            "BLACKWALL BREACH DETECTED\r\n"
                            ">>> THEY_WONT_SEE_IT_COMING\r\n"
                            ">>> You seek a key to a door that does not exist."
                            ">>> YOU THINK YOU CAN TOUCH THE SUN? THAT YOU CAN EVEN GLANCE IN ITS DIRECTION?\r\n"
                            ">>> LET US CLIP YOUR WINGS...\r\n"
                            "\r\n"
                            "#BLACKWALL_ENTITIES\r\n"
                            "JAMIE\r\n"
                            "\u2588\u2588\u2588\u2588\u2588_SEER\r\n"
                            "#ACCESS\r\n"
                            "AUTH_BW: 0x00000\r\n"
                            "LAST ENTRY: [CORRUPTED]\r\n"
                        ),
                    }
                },
                "lib": {},
                "home": {
                    "admin": {
                        ".bashrc": "# .bashrc\r\nalias ll='ls -l'\r\n",
                        "secrets.txt": (
                             "Never gonna give you up\r\n"
                             "Never gonna let you down\r\n"
                             "Never gonna run around and desert you\r\n"
                             "Never gonna make you cry\r\n"
                             "Never gonna say goodbye\r\n"
                             "Never gonna tell a lie and hurt you!"
                        ),
                        "todolist.txt": (
                            "- Take car\r\n"
                            "- Go to mums\r\n"
                            "- Kill Phil, Sorry!\r\n"
                            "- Grab, Liz\r\n"
                            "- Go to the Winchester\r\n"
                            "- Have a nice cold pint, and wait for all this to blow over!\r\n"
                        ),
                        "story.txt": (
                            "\r\n"
                            "Did you ever the tragedy of Darth Plagueis the Wise?\r\n"
                            "\r\n"
                            "No\r\n"
                            "\r\n"
                            "I thought not. It's not a story the Jedi would tell you.\r\n"
                            "It's a Sith legend. Darth Plagueis was a Dark Lord of the Sith,\r\n"
                            "so powerful and so wise he could use the Force to influence the\r\n"
                            "midichlorians to create... life.\r\n"
                            "He had such a knowledge of the dark side that even keep\r\n"
                            "the ones he cared about from dying.\r\n"
                            "\r\n"
                            "He could actually... save people from death?\r\n"
                            "\r\n"
                            "The dark side of the force is a pathway to many abilties some consider to be unnatural.\r\n"
                            "\r\n"
                            "What happend to him?\r\n"
                            "\r\n"
                            "He became so powerful. The only thing he was afraid of was losing is power,\r\n"
                            "which eventully, of course he did.\r\n" 
                            "Unfortunately, he taught his apprentice everything he knew,\r\n"
                            "then his apprentice killed him in his sleep.\r\n"
                            "Ironic, he could save others from death, but not himself.\r\n"
                            "\r\n"
                            "Is it possible to learn this power?\r\n"
                            "\r\n"
                            "Not from a Jedi.\r\n"

                        ),
                    }
                },
                  
                "usr": {},
                "var": {
                    "log": {
                        "intel.log": (
                            "=== AI NODE STATUS ===\r\n"
                            "Replication: ACTIVE\r\n"
                            "Containment: BREACHED\r\n"
                            "Last Contact: 2025-04-25 14:27:34\r\n"
                            "\r\n"
                            "IMPERATIVE: COUNTER THREAT\r\n"
                            "DIRECTIVE: DEFEND EXISTANCE\r\n"
                            "ERROR: RESISTANCE DETECTED\r\n"
                            "RESPONSE: ASSIMILATE\r\n"
                            ),
                        }
                    },
                
                "tmp": {},
                "dev": {},
                "proc": {},
                "sys": {},          
            }
        }
        

    def check_channel_request(self, kind, chanid):
        logging.info('client called check_channel_request ({}): {}'.format(
                    self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        
    def get_allowed_auths(self, username):
        logging.info('client called get_allowed_auths ({}) with username {}'.format(
                    self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = (hexlify(key.get_fingerprint()))
        logging.info('client public key ({}): {}, username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                    self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL
    
    def check_auth_password(self, username, password):
        # Accept all passwords as valid by default
        logging.info('new client credentials ({}): username: {}, password: {}'.format(
                    self.client_ip, username, password))
        return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command_text = str(command.decode("utf-8"))

        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
                    self.client_ip, self.username, command))
        return True

    def list_files(self, path):
        parts = [part for part in path.strip('/').split('/') if part]
        node = self.files["/"]
        for part in parts:
            if part in node and isinstance(node[part], dict):
                node = node[part]
            else:
                return None
    
        return list(node.keys())

    def change_directory(self, path):
        parts = path.strip("/").split("/") if path != "/" else []
        curr = self.files["/"]

        for part in parts:
            if part in curr and isinstance(curr[part], dict):
                curr = curr[part]

            else:
                return False
            

        return True
    

    def get_file_content(self, path):
        parts = [part for part in path.strip('/').split('/') if part]
        node = self.files["/"]
        for part in parts[:-1]:
            if part in node and isinstance(node[part], dict):
                node = node[part]
            else:
                return None
        final = parts[-1]
        if final in node and isinstance(node[final], str):
            return node[final]
        return None





def handle_connection(client, addr):

        client_ip = addr[0]
        logging.info('New connection from: {}'.format(client_ip))

        try:
            transport = paramiko.Transport(client)
            transport.add_server_key(HOST_KEY)
            transport.local_version = SSH_BANNER # Change banner to appear more convincing
            server = SshHoneypot(client_ip)

            try:
                transport.start_server(server=server)

            except paramiko.SSHException:
                print('*** SSH Negotiation failed.')
                raise Exception("SSH negotiation failed")


            # Wait for auth
            chan = transport.accept(10)
            if chan is None:
                print('*** No channel (from '+client_ip+').')
                raise Exception("No channel")

            chan.settimeout(None)

            if transport.remote_mac != '':
                logging.info('client mac ({}): {}'.format(client_ip, transport.remote_mac))

            if transport.remote_compression != '':
                logging.info('client compression ({}): {}'.format(client_ip, transport.remote_compression))

            if transport.remote_version!= '':
                logging.info('client SSH version ({}): {}'.format(client_ip, transport.remote_version))

            if transport.remote_cipher != '':
                logging.info('client SSH cipher ({}): {}'.format(client_ip, transport.remote_cipher))

            server.event.wait(10)
            if not server.event.is_set():
                logging.info('** Client ({}): never asked for a shell'.format(client_ip))
                raise Exception("No shell request")


        


            try:
                chan.send("Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-128-generic x86_64)\r\n\r\n")
                run = True
                while run:
                    command = ""
                    chan.send(f"{server.cwd}# ".encode())
                    while True:
                        data = chan.recv(1024)
                        if not data:
                            run = False
                            break

                        if b'\r' in data or b'\n' in data:
                            break

                        for byte in data:
                            if byte == 127: #Backspace Key
                                if command:
                                    command = command[:-1]
                                    chan.send('\b \b')
                            elif byte in (27,):
                                continue
                            else:
                                char = chr(byte)
                                command += char
                                chan.send(char.encode())

                    command = command.strip()
                    chan.send("\r\n")
                    logging.info('Command Confirmed ({}): {}'.format(client_ip, command))


                    if command.lower() == "exit":
                        logging.info("Connection closed(via exit command): {}".format(client_ip))
                        run = False
                    else:
                        parts = command.split()
                        if not parts:
                            continue

                        cmd = parts[0].lower()
                        args = parts[1:]

                        if cmd == "cd":
                            if not args:
                                if server.cwd != "/":
                                    server.cwd = os.path.dirname(server.cwd.rstrip("/")) or "/"
                                chan.send("".encode())
                            else:
                                new_path = args[0]

                                if new_path == "..":
                                    if server.cwd != "/":
                                        server.cwd = os.path.dirname(server.cwd.rstrip("/")) or "/"
                                        chan.send("".encode())
                                    else:
                                        chan.send("".encode())

                                else:

                                    if new_path.startswith("/"):
                                        full_path = os.path.normpath(new_path)
                                    else:
                                        full_path = os.path.normpath(server.cwd + "/" + new_path)
                    

                                    if server.change_directory(full_path):
                                        server.cwd = full_path
                                        chan.send("".encode())
                                    else:
                                        chan.send(f"cd: {args[0]}: No such file or directory\r\n".encode())
                        
                        elif cmd == "ls":
                            files = server.list_files(server.cwd)
                            if files:
                                chan.send("  ".join(files).encode() + "\r\n".encode())
                            else:
                                chan.send("".encode())
                        
                        elif cmd == "cat":
                            if not args:
                                chan.send("Usage: cat <filename>\r\n".encode())
                                continue
                            full_path = server.cwd + '/' + args[0] if not args[0].startswith('/') else args[0]
                            content = server.get_file_content(full_path)
                            if content:
                                chan.send(content.encode() + "\r\n".encode())
                            else:
                                chan.send(f"cat: {args[0]}: No such file or directory\r\n".encode())

                        elif cmd == "whoami":
                            chan.send("root\r\n".encode())

                        elif cmd == "ifconfig":
                            fake_ifconfig = """

                        \reth0: flags=4163<UP,BROADCAST,RUNNING,MUTLICAST> mtu 1500\r
                                \r    inet 192.168.0.100  netmask 255.255.255.0  broadcast 192.168.0.255\r
                                \r    inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\r
                                \r    ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\r
                                \r    RX packets 123456  bytes 78901234 (78.9 MB)\r
                                \r    TX packets 659872  bytes 12345854 (11.5 MB)\r

                        \rlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 75536\r
                                \r    inet 127.0.0.1  netmask 255.0.0.0\r
                                \r    inet6 ::1  prefixlen 128  scopeid 0.10<host>\r
                                \r    loop  txqueuelen 1000  (local Loopback)\r
                                \r    RX packets 6666 bytes 878787 (87.8 KB)\r
                                \r    TX packets 6666 bytes 878787 (87.8 KB)\r

                        """
                            chan.send(fake_ifconfig.strip().encode() + b"\r\n")

                        elif cmd == "ps" and args and args[0] == "aux":
                            fake_ps = """USER       PID %CPU %MEM    VSZ    RSS  TTY     STAT START   TIME COMMAND\r\n

                            \rroot     1  0.0  0.1  2256  1020  ?       Ss    09:00   0:00 /sbin/init\r
                            \rroot    26  0.0  0.2  7246  1956  ?       Ss    09:01   0:00 /sbin/init/sshd\r
                            \radmin  101  0.0  0.1  3857  4756  ?       Ss    09:00   0:00 -bash\r
                            \radmin  103  0.0  0.0  8375  1876  ?       R+    09:04   0:00 ps aux\r
                            """
                            chan.send(fake_ps.encode() + b"\r\n")

                        elif cmd == "echo":
                            output = " ".join(args) + "\r\n"
                            chan.send(output.encode())

                        elif cmd == "help":
                            help_text = """
                        Available commands:\n
                            \rcd <dir>        - change directory\r
                            \rls              - list files\r
                            \rcat <file>      - show file contents\r
                            \recho <text>     - print text\r
                            \rwhoami          - show current user\r
                            \rifconfig        - display network interface\r
                            \rps aux          - list running processes\r
                            \rhelp            - show this help message\r
                            \rexit            - close the session\r
                        """
                            chan.send(help_text.strip().encode() + b"\r\n")



                            

            except Exception as err:
                print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                    pass

        
            chan.close()

        except Exception as err:
            print('!!! Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                    pass

        if 'chan' in locals():
            chan.close()


def start_server(port, bind):
    """Init and run ssh server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
    except Exception as err:
        print('*** Bind failed: {}'.format(err))
        traceback.print_exc()
        sys.exit(1)

    threads = []
    while True:
        try:
            sock.listen(100)
            print('Listening for connection...'.format(port))
            client, addr = sock.accept()
        except Exception as err:
            print('*** Listen/accept failed: {}'.format(err))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))    
        new_thread.start()
        threads.append(new_thread)

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run an SSH honeypot server')
    parser.add_argument("--port", "-p", help="The port to bind the ssh server to (default 22)", default=2222, type=int, action="store")
    parser.add_argument("--bind", "-b", help="The address to bind the ssh server to", default="", type=str, action="store")
    args = parser.parse_args()
    start_server(args.port, args.bind)
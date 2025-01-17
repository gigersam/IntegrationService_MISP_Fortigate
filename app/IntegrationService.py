import socket
import os
import signal
import requests
from threading import Thread
from queue import Queue
from Config import MISP_SERVER, MISP_API_KEY, FORTIGATE_IP, FORTIGATE_API_KEY, BLOCK_GROUP_NAME, TO_CHECK_OBJECTS
import urllib3
import re
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Fortigate:
    def __init__(self, fortigate_addr="0.0.0.0", fortigate_key="", verify_ssl=False): 
        self.fortigate_addr = fortigate_addr
        self.fortigate_key = fortigate_key
        self.verify_ssl = verify_ssl
        self.headers = headers = {
            "Authorization": f"Bearer {self.fortigate_key}",
            "Content-Type": "application/json"
        }

    def get_address_object(self, object_name):
        object_name = object_name.replace("/", "%2F")
        url = f"https://{self.fortigate_addr}/api/v2/cmdb/firewall/address/{object_name}"
        response = requests.get(url, headers=self.headers, verify=False)

        if response.status_code == 200:
            address_object = response.json()
            return 1
        elif response.status_code == 404:
            return 0
        else:
            return 0

    def add_address_object(self, ip):
        url = f"https://{self.fortigate_addr}/api/v2/cmdb/firewall/address"
        payload = {
            "name": ip,
            "subnet": ip,
            "associated-interface": {
                "q_origin_key": "wan1"
            },
            "comment": "IntegrationService:" + str(datetime.datetime.now())
        }
        response = requests.post(url, headers=self.headers, json=payload, verify=False)
    
        if response.status_code == 200:
            print(f"Address object '{ip}' created successfully.")
            return 0
        else:
            print(f"Failed to create address object. Error: {response.text}")
            return 1
    
    def add_address_object_to_group(self, object, group):
        url = f"https://{self.fortigate_addr}/api/v2/cmdb/firewall/addrgrp/{group}"
        # Get the current members of the group
        response = requests.get(url, headers=self.headers, verify=False)
        if response.status_code != 200:
            print(f"Failed to get address group details. Error: {response.text}")
            return

        group_data = response.json()
        results = group_data.get('results', [])
        if not results:
            print("No address groups found.")
            return

        # Find the specific group
        group = next((g for g in results if g.get('name') == group), None)
        if not group:
            print(f"Address group '{group}' not found.")
            return

        # Get the current members of the group
        members = group.get('member', [])
        print(members)
        members.append({"name": object})

        # Update the address group with the new member
        payload = {
            "member": members
        }
        response = requests.put(url, headers=self.headers, json=payload, verify=False)

        if response.status_code == 200:
            return 0
        else:
            print(f"Failed to add address object to group. Error: {response.text}")
            return 1
    
    def add_ip_block(self, ip, group):
        block_object = ip + "/32"
        object_exists = self.get_address_object(object_name=block_object)
        if object_exists == 0:
            add_object = self.add_address_object(ip=block_object)
            if add_object == 0:
                add_object_group = self.add_address_object_to_group(object=block_object, group=group)
                if add_object_group == 1:
                    print("Failed to add object to Group")
            else:
                print("Failed to add object to Group")
        else:
            add_object_group = self.add_address_object_to_group(object=block_object, group=group)
            if add_object_group == 1:
                print("Failed to add object to Group")

  

class MISP:
    def __init__(self, mispaddr="0.0.0.0", misp_key="", verify_ssl=False): 
        self.mispaddr = mispaddr
        self.misp_key = misp_key
        self.verify_ssl = verify_ssl
        self.headers = headers = {
            'Authorization': self.misp_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def query_misp(self, query):
        # Make the request
        url = f"https://{self.mispaddr}/attributes/restSearch"
        response = requests.post(url, headers=self.headers, json=query, verify=self.verify_ssl)
        return response

    def check_ipv4(self, ip):
        
        query = {
            "returnFormat": "json",
            "type": "ip-dst",
            "value": ip
        }

        # Make the request
        response = self.query_misp(query=query)

        # Check if the request was successful
        if response.status_code == 200:
            result = response.json()
            result = result['response']
            # result is a dictionary containing "Attribute" (if matches found)
            if 'Attribute' in result and len(result['Attribute']) > 0:
                return 1
            else:
                return 0
        else:
            return "Response:", response.text

class SyslogServer:
    def __init__(self, host="0.0.0.0", port=514):
        self.host = host
        self.port = port
        self.running = True
        self.sock = None
        self.message_queue = Queue()

    def stop(self):
        """Stop the server and close the socket."""
        self.running = False
        if self.sock:
            self.sock.close()
            print(f"Closed the socket on {self.host}:{self.port}")

    def start(self):
        try:
            # Create a UDP socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Bind the socket to the specified host and port
            self.sock.bind((self.host, self.port))

            print(f"Syslog server listening on {self.host}:{self.port} (UDP)")

            while self.running:
                try:
                    # Receive data from clients
                    data, addr = self.sock.recvfrom(4096)  # Buffer size of 4096 bytes

                    # Decode the received data
                    decoded_data = data.decode('utf-8', errors='replace')

                    # Add the raw message to the queue
                    self.message_queue.put((addr, decoded_data))

                    # Log the raw message
                    #print(f"Raw message from {addr}: {decoded_data}")
                except socket.timeout:
                    continue

        except PermissionError:
            print("Error: Permission denied. Try running as root or using a privileged port workaround.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.stop()

class MessageAnalyzer:
    def __init__(self, message_queue):
        self.message_queue = message_queue
        self.running = True

    def parse_message(self, data):
        """Parse the syslog message using predefined patterns."""
        syslog_pattern = re.compile(r"<(\d+)>([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^\s]+)\s+(.*)")
        match = syslog_pattern.match(data)
        if match:
            priority, timestamp, hostname, app_name, msg_content = match.groups()
            msg_content = msg_content.replace("\x00", "")
            return {
                "priority": priority,
                "timestamp": timestamp,
                "hostname": hostname,
                "app_name": app_name,
                "message": msg_content
            }
        else:
            custom_pattern = re.compile(r'<(\d+)>date=(\d{4}-\d{2}-\d{2}) time=(\d{2}:\d{2}:\d{2}) devname="([^"]*)" devid="([^"]*)" (.*)')
            match = custom_pattern.match(data)
            if match:
                priority, date, time, devname, devid, msg_content = match.groups()
                timestamp = f"{date} {time}"
                msg_content = msg_content.replace("\x00", "")
                return {
                    "priority": priority,
                    "timestamp": timestamp,
                    "hostname": devname,
                    "app_name": devid,
                    "message": msg_content
                }
        return None

    def parse_message_fields(self, msg_content):
        """Parse key-value pairs from the message content."""
        field_pattern = re.compile(r'(\w+)="(.*?)"|(\w+)=([^\s]+)')
        fields = {}
        for match in field_pattern.finditer(msg_content):
            key = match.group(1) or match.group(3)
            value = match.group(2) or match.group(4)
            fields[key] = value
        return fields

    def analyze_message(self):
        """Continuously fetch and analyze messages from the queue."""
        misp = MISP(mispaddr=MISP_SERVER, misp_key=MISP_API_KEY)
        fortigate = Fortigate(fortigate_addr=FORTIGATE_IP, fortigate_key=FORTIGATE_API_KEY)
        while self.running:
            if not self.message_queue.empty():
                addr, data = self.message_queue.get()

                # Parse the syslog message
                parsed_message = self.parse_message(data)
                try:
                    if parsed_message:
                        # Further parse fields in the message content
                        if "message" in parsed_message:
                            parsed_message["fields"] = self.parse_message_fields(parsed_message["message"])
                            for item in TO_CHECK_OBJECTS:
                                if parsed_message["fields"]["policyid"] == item[0] and parsed_message["fields"]["action"] == item[1]:
                                    misp_result = misp.check_ipv4(ip=parsed_message["fields"]["srcip"])
                                    if misp_result == 1:
                                        fortigate.add_ip_block(ip=parsed_message["fields"]["srcip"], group=BLOCK_GROUP_NAME)

                        # Example: Check if the message contains a specific keyword
                        if "error" in parsed_message.get("fields", {}).get("message", "").lower():
                            print(f"Alert! Error found in message from {addr}: {parsed_message}")
                    else:
                        print(f"Failed to parse message from {addr}: {data}")
                except:
                    continue

    def start(self):
        """Start the analyzer in a separate thread."""
        analyzer_thread = Thread(target=self.analyze_message)
        analyzer_thread.daemon = True
        analyzer_thread.start()
        print("Message analyzer started.")

if __name__ == "__main__":
    server = SyslogServer()
    analyzer = MessageAnalyzer(server.message_queue)

    def signal_handler(sig, frame):
        print("\nShutting down...")
        server.stop()
        analyzer.running = False

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start the server in a separate thread
    server_thread = Thread(target=server.start)
    server_thread.start()

    # Start the message analyzer
    analyzer.start()

    # Wait for the server thread to finish
    server_thread.join()

import requests
import urllib3
from datetime import datetime, timedelta
import signal
import json
import time
import sys
from threading import Thread
from Config import MISP_SERVER, MISP_API_KEY, FORTIGATE_IP, FORTIGATE_API_KEY, BLOCK_GROUP_NAME, MISP_FEED_UPDATE_CYCLE, FORTIGATE_ADDRESS_OBJECTS_REMOVE_CYCLE

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
        self.fortigate_remove_address_object_cycle = FORTIGATE_ADDRESS_OBJECTS_REMOVE_CYCLE

    def get_address_objects(self):
        url = f"https://{self.fortigate_addr}/api/v2/cmdb/firewall/address"
        response = requests.get(url, headers=self.headers, verify=False)

        if response.status_code == 200:
            address_object = response.json()
            return address_object
        elif response.status_code == 404:
            return 1
        else:
            return 1
        
    def remove_address_object_from_group(self, object, group):
        url = f"https://{self.fortigate_addr}/api/v2/cmdb/firewall/addrgrp/{group}"
        response = requests.get(url, headers=self.headers, verify=False)

        if response.status_code != 200:
            print(f"Error fetching group: {response.text}")
            return response

        group_data = response.json()
        results = group_data.get('results', [])
        if not results:
            print("No address groups found.")
            return
        # Find the specific group
        group_object = next((g for g in results if g.get('name') == group), None)
        if not group:
            print(f"Address group '{group_object}' not found.")
            return
        # Get the current members of the group
        members = group_object.get('member', [])
        updated_members = [member for member in members if member['name'] != object]

        # Update the group configuration
        payload = {
            "member": updated_members
        }

        response = requests.put(url, headers=self.headers, json=payload, verify=False)

        print(payload)
        if response.status_code == 200:
            print(f"Successfully removed {object} from {group}.")
            return True
        else:
            print(f"Error updating group: {response.text}")
            return False
        

    def remove_address_object(self, object):
        object_parsed = object.replace("/", "%2F")
        url = f"https://{self.fortigate_addr}/api/v2/cmdb/firewall/address/{object_parsed}"
        response = requests.delete(url, headers=self.headers, verify=False)
        if response.status_code == 200:
            print(f"Successfully removed address object {object}.")
            return True
        else:
            print(f"Error removing address object: {response.text}")
            return False

    
    def remove_ip_block(self, object, group):
        remove_object_group = self.remove_address_object_from_group(object=object, group=group)
        if remove_object_group:
            remove_object = self.remove_address_object(object=object)
            if remove_object:
                return True
            else:
                return False
        else: 
            return False

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
        self.misp_feed_update_cycle = MISP_FEED_UPDATE_CYCLE

    def fetch_feeds(self):
        url = f"https://{self.mispaddr}/feeds/fetchFromAllFeeds"
        try:
            response = requests.post(url, headers=self.headers, verify=self.verify_ssl)

            # Check for successful response
            if response.status_code == 200:
                print("Feeds successfully updated.")
                print("Response:", json.dumps(response.json(), indent=4))
            else:
                print(f"Failed to update feeds. HTTP Status: {response.status_code}")
                print("Error message:", response.text)

        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")


class Housekeeping:
    def __init__(self):
        self.fortigate = Fortigate(fortigate_addr=FORTIGATE_IP, fortigate_key=FORTIGATE_API_KEY)
        self.misp = MISP(mispaddr=MISP_SERVER, misp_key=MISP_API_KEY)
        self.running = True

    def housekeeping_fortigate(self):
        while self.running:
            check_date = datetime.now() - timedelta(days=90)
            objects = self.fortigate.get_address_objects()
            if objects != 1:
                for object in objects["results"]:
                    if object["comment"] != "" or object["comment"] != "Created for DHCP Reservation":
                        try:
                            if datetime.strptime(object["comment"], '%Y-%m-%d %H:%M:%S.%f') < check_date:
                                self.fortigate.remove_ip_block(object=object["name"], group=BLOCK_GROUP_NAME)
                            else:
                                continue
                        except:
                            continue
            time.sleep(self.fortigate.fortigate_remove_address_object_cycle)

    def housekeeping_misp(self):
        while self.running:
            self.misp.fetch_feeds()
            time.sleep(self.misp.misp_feed_update_cycle)

    def start(self):
        """Start the housekeeping_thread in a separate thread."""
        housekeeping_fortigate_thread = Thread(target=self.housekeeping_fortigate)
        housekeeping_fortigate_thread.daemon = True
        housekeeping_fortigate_thread.start()
        print("Message housekeeping_misp_thread started.")

        housekeeping_misp_thread = Thread(target=self.housekeeping_misp)
        housekeeping_misp_thread.daemon = True
        housekeeping_misp_thread.start()
        print("Message housekeeping_misp_thread started.")

        housekeeping_fortigate_thread.join()
        housekeeping_misp_thread.join()

if __name__ == "__main__":
    housekeeping = Housekeeping()
    def signal_handler(sig, frame):
        print("\nShutting down...")
        housekeeping.running = False
        sys.exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    housekeeping.start()

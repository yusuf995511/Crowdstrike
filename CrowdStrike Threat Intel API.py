from falconpy import *
from falconpy import APIHarnessV2
import pandas as pd
import time
import os
import sys
import json
import socket

# Create an APIHarnessV2 object to connect to Crowdstrike.
falcon = APIHarnessV2(client_id="your_client_id_here",
                      client_secret="your_client_secret_here"
                      )

#Path to save the CSV file ( Use // for Windows)
Path = "Path of your choice"

# Initialize the marker to None
marker = None

#This code sets the wait time between each request to CrowdStrike.
Wait = 5

# Define a function to gather the threat intelligence from Crowdstrike.
def gather_threat_intel_offset():
    """Gathers the threat intelligence from Crowdstrike.

    Returns:
        A list of threat intelligence indicators.
    """
    try:
        limit = 5000  # Number of records to retrieve per request
        offset = 0    # Initial offset
        threat_intel_list = []  # List to store all threat intelligence
        while True:
            response = falcon.command("QueryIntelIndicatorEntities", limit=limit, offset=offset)
            resources = response.get('body', {}).get('resources', [])
            x_ratelimit_remaining = response['headers']['X-Ratelimit-Remaining']
            prCyan("X-Ratelimit-Remaining: "+ x_ratelimit_remaining)
            
            # Break the loop if no more data is available
            if not resources:
                break
            print(f"Gathered {len(resources)} threat intelligence records.")

            # Extract and append the relevant fields from the JSON response
            for item in resources:
                if isinstance(item, dict):
                    threat_intel_item = {
                        'id': item.get('id', ''),
                        'indicator': item.get('indicator', ''),
                        'type': item.get('type', ''),
                        'deleted': item.get('deleted', False),
                        'published_date': item.get('published_date', ''),
                        'last_updated': item.get('last_updated', ''),
                        'reports': item.get('reports', []),
                        'actors': item.get('actors', []),
                        'malware_families': item.get('malware_families', []),
                        'kill_chains': item.get('kill_chains', []),
                        'ip_address_types': item.get('ip_address_types', []),
                        'domain_types': item.get('domain_types', []),
                        'malicious_confidence': item.get('malicious_confidence', ''),
                        '_marker': item.get('_marker', ''),
                        'labels': item.get('labels', []),
                        'relations': item.get('relations', []),
                        'targets': item.get('targets', []),
                        'threat_types': item.get('threat_types', []),
                        'vulnerabilities': item.get('vulnerabilities', []),
                        'errors': item.get('errors', []) if isinstance(item.get('errors', []), list) else []
                    }
                    threat_intel_list.append(threat_intel_item)

            # Increment the offset to fetch the next chunk of data
            offset += limit
        print(f"Total threat intelligence records gathered: {len(threat_intel_list)}")
        return threat_intel_list
    except APIError as e:
        prRed(f"Error gathering threat intelligence: {e}")
        return None

# Define a function to gather the threat intelligence from Crowdstrike.
def gather_threat_intel(marker):
    """Gathers the threat intelligence from Crowdstrike.

    Args:
        marker (str): The marker to use for paginating through the data.

    Returns:
        A tuple containing the new marker and a list of threat intelligence indicators.
    """

    limit = 5000  # Number of records to retrieve per request
    threat_intel_list = []  # List to store all threat intelligence

    try:
        response = falcon.command("QueryIntelIndicatorEntities", limit=limit, _marker=marker)
         # get theX-Ratelimit-Remaining
        x_ratelimit_remaining = response['headers']['X-Ratelimit-Remaining']
        prCyan("X-Ratelimit-Remaining: "+ x_ratelimit_remaining)
        
        resources = response.get('body', {}).get('resources', [])
        
        
        print("Gathered threat intelligence successfully.")
        
        # Extract the relevant fields from the JSON response
        for item in resources:
                if isinstance(item, dict):

                    # Check if the indicator is not already in the set (no duplicates)
                    new_marker = item.get('_marker', '')
                    threat_intel_item = {
                        'id': item.get('id', ''),
                        'indicator': item.get('indicator', ''),
                        'type': item.get('type', ''),
                        'deleted': item.get('deleted', False),
                        'published_date': item.get('published_date', ''),
                        'last_updated': item.get('last_updated', ''),
                        'reports': item.get('reports', []),
                        'actors': item.get('actors', []),
                        'malware_families': item.get('malware_families', []),
                        'kill_chains': item.get('kill_chains', []),
                        'ip_address_types': item.get('ip_address_types', []),
                        'domain_types': item.get('domain_types', []),
                        'malicious_confidence': item.get('malicious_confidence', ''),
                        '_marker': item.get('_marker', ''),
                        'labels': item.get('labels', []),
                        'relations': item.get('relations', []),
                        'targets': item.get('targets', []),
                        'threat_types': item.get('threat_types', []),
                        'vulnerabilities': item.get('vulnerabilities', []),
                        'errors': item.get('errors', []) if isinstance(item.get('errors', []), list) else []
                    }
                    threat_intel_list.append(threat_intel_item)
        return new_marker, threat_intel_list
    except APIError as e:
        prRed(f"Error gathering threat intelligence: {e}")
        return None

# Define a function to append new threat intelligence to an existing CSV file.
def append_threat_intel_to_csv(threat_intel):
    """Appends new threat intelligence to an existing CSV file.

    Args:
        threat_intel: A list of threat intelligence indicators.
    """
    try:
        file_path = Path + 'threat_intel.csv'

        # If the CSV file exists, append to it; otherwise, create a new CSV file.
        if os.path.exists(file_path):
            df = pd.read_csv(file_path)
            df = pd.concat([df, pd.DataFrame(threat_intel)], ignore_index=True)
        else:
            df = pd.DataFrame(threat_intel)

        df.to_csv(file_path, index=False)
        print("Appended threat intelligence to 'threat_intel.csv' successfully.")
    except Exception as e:
        prRed(f"Error appending threat intelligence: {e}")

def db_connetion (indicators):
    print("[+] Connecting to DB")
    IP = "127.0.0.1"
    #JSON
    PORT = 5500
    print("[+] Connecting to " + str(IP)+":"+str(PORT))
    for x in indicators:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # initalising socket and UDP connection
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # connecting to the server
            # print("[+] Connecting to " + str(IP)+":"+str(PORT))
            s.connect((IP, PORT))
            # print("[+] Connected.")
            r=(json.dumps(x))
            s.sendto(r.encode('utf-8'), (IP, PORT))
            # print("SENT to:-", IP,":", PORT)
        except Exception as msg:
            print(f"Error sending threat intelligence: {msg}")
        finally:
            s.close()

    print("indicators are Sent to:-", IP,":", PORT)

def prRed(skk): print("\033[91m{}\033[00m".format(skk))
def prYellow(skk): print("\033[93m{}\033[00m".format(skk))
def prGreen(skk): print("\033[92m{}\033[00m".format(skk))
def prCyan(skk): print("\033[96m{}\033[00m".format(skk))

def welcome_page():
  """Displays a welcome page to the user and prompts them to choose between running continuously or saving the results to a CSV file."""
  
  prRed("*********************************************************************")
  print("")
  prYellow("   Welcome to the CrowdStrike Threat Intelligence Automation!")
  print("")
  prRed("*********************************************************************")
  prCyan("Please choose one of the following options:")
  prGreen("1. Fowrwarding logs to a DB ( marker )")
  prGreen("2. Fowrwarding logs to a DB ( offset to marker )")
  prGreen("3. Run continuously to fetch threat intel ( marker - CSV) ")
  prGreen("4. Run continuously to fetch threat intel ( offset to marker - CSV) ")
  prGreen("5. anything else to exit")

# Define a function to get a valid integer input from the user.
def get_valid_integer_input(prompt):
    while True:
        user_input = input(prompt)
        try:
            value = int(user_input)
            return value
        except ValueError:
            prRed("Invalid input. Please enter a valid integer.")
             
# Define a main function to run the script continuously.
def main():
    first_time = 1
    global marker  # Declare marker as a global variable

    #Displays a welcome page
    welcome_page()

    #enter choice
    choice = input("Enter your choice ( 1,2,3 or 4): ")
    prRed("*********************************************************************")

    if choice == "1":
        while True:
            try:
                if marker is None:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                    if threat_intel is not None:
                        # Append the new threat intelligence to the CSV file.
                        db_connetion(threat_intel)
                    # Update the marker with the new marker value.
                    marker = new_marker
                    print("Waiting for "+ str(Wait) + " seconds before the next check.")
                    time.sleep(Wait)
                while marker is not None:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                    if threat_intel is not None:
                        # Append the new threat intelligence to the CSV file.
                        db_connetion(threat_intel)
                        print("[+] ")
                    # Update the marker with the new marker value.
                    marker = new_marker
                # Waiting the next check.
                    print("Waiting for "+ str(Wait) + " seconds before the next check.")
                    time.sleep(Wait)

            except Exception as e:
                prRed(f"Error: {e}")
                print("Waiting for "+ str(Wait) + " seconds before the next check.")
                time.sleep(Wait)
                
    elif choice == "2":
        while True:
            try:
                if (first_time == 1):
                    try:
                        threat_intel=gather_threat_intel_offset()
                        db_connetion(threat_intel)
                        time.sleep(Wait)
                        
                    except Exception as e:
                        prRed(f"Error: {e}")
                        time.sleep(Wait)
                    first_time = 0
                else:
                    if marker is None:
                        # Gather the threat intelligence from Crowdstrike with the current marker.
                        new_marker, threat_intel = gather_threat_intel(marker)

                        if threat_intel is not None:
                            # Append the new threat intelligence to the CSV file.
                            db_connetion(threat_intel)

                        # Update the marker with the new marker value.
                        marker = new_marker
                        print("Waiting for "+ str(Wait) + " seconds before the next check.")
                        time.sleep(Wait)
                    while marker is not None:
                        # Gather the threat intelligence from Crowdstrike with the current marker.
                        new_marker, threat_intel = gather_threat_intel(marker)

                        if threat_intel is not None:
                            # Append the new threat intelligence to the CSV file.
                            db_connetion(threat_intel)

                        # Update the marker with the new marker value.
                        marker = new_marker

                        # wait for the next check.
                        print("Waiting for "+ str(Wait) + " seconds before the next check.")
                        time.sleep(Wait)

            except Exception as e:
                print(f"Error: {e}")
                print("Waiting for " + str(Wait) + " seconds before the next check.")
                time.sleep(Wait)
    elif choice == "3":

        # Ask the user for the time to run in minutes
        run_time_minutes = get_valid_integer_input("Enter the time to run (in minutes): ")
        try:
            run_time_minutes = int(run_time_minutes)
        except ValueError:
            prRed("Invalid input. Please enter a valid integer for the run time in minutes.")
            sys.exit()

        run_time_seconds = run_time_minutes * 60
        start_time = time.time()
        end_time = start_time + run_time_seconds

        while time.time() < end_time:
            try:
                if marker is None:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                    print("Waiting for "+ str(Wait) + " seconds before the next check.")
                    time.sleep(Wait)
                    if threat_intel is not None:
                        # Append the new threat intelligence to the CSV file.
                        append_threat_intel_to_csv(threat_intel)
                    # Update the marker with the new marker value.
                    marker = new_marker
                while marker is not None:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                    if threat_intel is not None:
                        # Append the new threat intelligence to the CSV file.
                        append_threat_intel_to_csv(threat_intel)
                    # Update the marker with the new marker value.
                    marker = new_marker
                    if time.time() >= end_time:
                        prYellow(str(run_time_minutes)+ " minutes finished")
                        prYellow("Exit")
                        break  # Exit the loop if the time limit is reached
                    # wait for the next check.
                    print("Waiting for "+ str(Wait)+ " seconds before the next check.")
                    time.sleep(Wait)
            except Exception as e:
                prRed(f"Error: {e}")
                
    elif choice == "4":
        # Ask the user for the time to run in minutes
        run_time_minutes = get_valid_integer_input("Enter the time to run (in minutes): ")
        try:
            run_time_minutes = int(run_time_minutes)
        except ValueError:
            prRed("Invalid input. Please enter a valid integer for the run time in minutes.")
            sys.exit()

        run_time_seconds = run_time_minutes * 60
        start_time = time.time()
        end_time = start_time + run_time_seconds

        while time.time() < end_time:
            try:
                if (first_time == 1):
                    print("*** starting offset ***")
                    try:
                        threat_intel=gather_threat_intel_offset()
                        append_threat_intel_to_csv(threat_intel)
                        
                    except Exception as e:
                        prRed(f"Error: {e}")

                    first_time = 0
                    # wait for the next check. and jumb to marker
                    print("Waiting for "+ str(Wait) + " seconds before the next check.")
                    time.sleep(Wait)
                else:
                    print ("*** jumping to marker ***")
                    if marker is None:
                        # Gather the threat intelligence from Crowdstrike with the current marker.
                        new_marker, threat_intel = gather_threat_intel(marker)
                        print("Waiting for "+ str(Wait) + " seconds before the next check.")
                        time.sleep(Wait)

                        if threat_intel is not None:
                            # Append the new threat intelligence to the CSV file.
                            append_threat_intel_to_csv(threat_intel)

                        # Update the marker with the new marker value.
                        marker = new_marker
                        
                        # wait for the next check.
                        print("Waiting for"+ str(Wait) + " seconds before the next check.")
                        time.sleep(Wait)

                    while marker is not None:
                        # Gather the threat intelligence from Crowdstrike with the current marker.
                        new_marker, threat_intel = gather_threat_intel(marker)

                        if threat_intel is not None:
                            # Append the new threat intelligence to the CSV file.
                            append_threat_intel_to_csv(threat_intel)

                        # Update the marker with the new marker value.
                        marker = new_marker
                        if time.time() >= end_time:
                            prYellow(str(run_time_minutes)+ " minutes finished")
                            prYellow("Exit")
                            break  # Exit the loop if the time limit is reached
                        # wait for the next check.
                        print("Waiting for"+ str(Wait) + " seconds before the next check.")
                        time.sleep(Wait)
                
            except Exception as e:
                print(f"Error: {e}")
                print("Waiting for" + str(Wait) + " seconds before the next check.")
                time.sleep(Wait)
    else:
        print("Invalid choice.")
        sys.exit()
    
if __name__ == '__main__':
    main()
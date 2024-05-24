import logging
from falconpy import APIHarnessV2, APIError
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
# Path to save the CSV file ( Use // for Windows)
Path = "Path of your choice"
# Initialize the marker to None
marker = None
# This code sets the wait time between each request to CrowdStrike.
Wait = 5
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            logging.info(f"X-Ratelimit-Remaining: {x_ratelimit_remaining}")
            
            # Break the loop if no more data is available
            if not resources:
                break
            logging.info(f"Gathered {len(resources)} threat intelligence records.")

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
        logging.info(f"Total threat intelligence records gathered: {len(threat_intel_list)}")
        return threat_intel_list
    except APIError as e:
        logging.error(f"Error gathering threat intelligence: {e}")
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
        x_ratelimit_remaining = response['headers']['X-Ratelimit-Remaining']
        logging.info(f"X-Ratelimit-Remaining: {x_ratelimit_remaining}")
        
        resources = response.get('body', {}).get('resources', [])
        logging.info("Gathered threat intelligence successfully.")
        
        # Extract the relevant fields from the JSON response
        for item in resources:
            if isinstance(item, dict):
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
        logging.error(f"Error gathering threat intelligence: {e}")
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
        logging.info("Appended threat intelligence to 'threat_intel.csv' successfully.")
    except Exception as e:
        logging.error(f"Error appending threat intelligence: {e}")

def db_connetion (indicators):
    logging.info("[+] Connecting to DB")
    IP = "127.0.0.1"
    PORT = 5500
    logging.info(f"[+] Connecting to {IP}:{PORT}")
    for x in indicators:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Initialising socket and UDP connection
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.connect((IP, PORT))
            r = json.dumps(x)
            s.sendto(r.encode('utf-8'), (IP, PORT))
        except Exception as msg:
            logging.error(f"Error sending threat intelligence: {msg}")
        finally:
            s.close()

    logging.info(f"Indicators are sent to: {IP}:{PORT}")

def welcome_page():
    """Displays a welcome page to the user and prompts them to choose between running continuously or saving the results to a CSV file."""
    logging.info("")
    logging.info("*********************************************************************")
    logging.info("")
    logging.info("   Welcome to the CrowdStrike Threat Intelligence Automation!")
    logging.info("")
    logging.info("*********************************************************************")
    logging.info("Please choose one of the following options:")
    logging.info("1. Forwarding logs to a DB (marker)")
    logging.info("2. Forwarding logs to a DB (offset to marker)")
    logging.info("3. Run continuously to fetch threat intel (marker - CSV)")
    logging.info("4. Run continuously to fetch threat intel (offset to marker - CSV)")
    logging.info("5. Anything else to exit")

# Define a function to get a valid integer input from the user.
def get_valid_integer_input(prompt):
    while True:
        user_input = input(prompt)
        try:
            value = int(user_input)
            return value
        except ValueError:
            logging.error("Invalid input. Please enter a valid integer.")

# Define a main function to run the script continuously.
def main():
    first_time = 1
    global marker  # Declare marker as a global variable

    # Displays a welcome page
    welcome_page()

    # Enter choice
    choice = input("Enter your choice (1, 2, 3, or 4): ")
    logging.info("*********************************************************************")

    if choice == "1":
        while True:
            try:
                if marker is None:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                else:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                    logging.info(f"Previous Marker: {marker}")

                if threat_intel is not None:
                    logging.info(f"Gathered threat intelligence records with marker: {marker}")

                    # Call the db_connetion function to send the threat intelligence to the database.
                    db_connetion(threat_intel)
                else:
                    logging.error("No threat intelligence gathered.")
                    break

                marker = new_marker  # Update the marker for the next iteration.
                logging.info(f"Updated marker: {marker}")

                time.sleep(Wait)  # Wait for the specified time before the next request.
            except Exception as e:
                logging.error(f"Error: {e}")
                break

    elif choice == "2":
        while True:
            try:
                # Gather the threat intelligence from Crowdstrike with the current offset.
                threat_intel = gather_threat_intel_offset()
                if threat_intel is not None:
                    logging.info("Gathered threat intelligence records with offset.")
                    # Call the db_connetion function to send the threat intelligence to the database.
                    db_connetion(threat_intel)
                else:
                    logging.error("No threat intelligence gathered.")
                    break
                time.sleep(Wait)  # Wait for the specified time before the next request.
            except Exception as e:
                logging.error(f"Error: {e}")
                break

    elif choice == "3":
        while True:
            try:
                if marker is None:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                else:
                    # Gather the threat intelligence from Crowdstrike with the current marker.
                    new_marker, threat_intel = gather_threat_intel(marker)
                    logging.info(f"Previous Marker: {marker}")

                if threat_intel is not None:
                    logging.info(f"Gathered threat intelligence records with marker: {marker}")

                    # Append the gathered threat intelligence to the CSV file.
                    append_threat_intel_to_csv(threat_intel)
                else:
                    logging.error("No threat intelligence gathered.")
                    break

                marker = new_marker  # Update the marker for the next iteration.
                logging.info(f"Updated marker: {marker}")

                time.sleep(Wait)  # Wait for the specified time before the next request.
            except Exception as e:
                logging.error(f"Error: {e}")
                break

    elif choice == "4":
        while True:
            try:
                # Gather the threat intelligence from Crowdstrike with the current offset.
                threat_intel = gather_threat_intel_offset()
                if threat_intel is not None:
                    logging.info("Gathered threat intelligence records with offset.")
                    # Append the gathered threat intelligence to the CSV file.
                    append_threat_intel_to_csv(threat_intel)
                else:
                    logging.error("No threat intelligence gathered.")
                    break
                time.sleep(Wait)  # Wait for the specified time before the next request.
            except Exception as e:
                logging.error(f"Error: {e}")
                break

    else:
        logging.info("Exiting the script.")
        sys.exit()

if __name__ == "__main__":
    main()

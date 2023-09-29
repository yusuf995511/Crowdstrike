# Crowdstrike Threat Intelligence Automation

This script automates the retrieval of threat intelligence indicators from Crowdstrike using the Crowdstrike API and allows you to forward the obtained threat intelligence to a database. It also provides options for continuous execution with different marker and offset settings.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python (3.x) installed on your system.
- Crowdstrike API credentials (`client_id` and `client_secret`) obtained and ready.

## Getting Started

### Installation

1. Clone this repository to your local machine or download the script file.
   ```bash
   git clone https://github.com/yusuf995511/Crowdstrike
   ```

2. Navigate to the project directory:
   ```bash
   cd Crowdstrike
   ```
   
3. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

4. Run the requiremnt file.
   ```bash
   pip install -r requirements.txt
   ```

# Configuration
1. Before running the script, you need to configure your Crowdstrike API credentials. Edit the script file (crowdstrike_automation.py) and locate the following section:
   Create an APIHarnessV2 object to connect to Crowdstrike.
   ```python
      falcon = APIHarnessV2(client_id="your_client_id_here",
                      client_secret="your_client_secret_here"
                      )
   ```
   Replace `your_client_id_here` and `your_client_secret_here` with your actual Crowdstrike API credentials.

 2. Change the path were you want to save the csv file:
   ```python
      #Path to save the CSV file ( Use // for windows)
      Path = "Path of your choice"
   ```
3. Change the IP and the port if you don't want to send it to the localhost
   ```python
   # By default
      IP = "127.0.0.1"
      PORT = 5500
   ```

# Usage
To run the script, open a terminal and navigate to the project directory. Then, execute the following command:
   ```python
   python crowdstrike_automation.py
   ```

# Options
The script provides the following options:
1. Forwarding threat intelligence to a database with marker.
2. Forwarding threat intelligence to a database with offset to marker.
3. Running continuously to fetch threat intel using marker and saving results to a CSV file.
4. Running continuously to fetch threat intel using offset to marker and saving results to a CSV file.
5. Exit (for other choices).

# Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or create a pull request.


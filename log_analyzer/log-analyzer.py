import re
import datetime
from datetime import datetime as dt
import matplotlib.pyplot as plt
from collections import Counter


# ********************************************************************
# *** create a datetime object to record the date ********************
# ********************************************************************
current_time = datetime.datetime.now()
current_time_str = current_time.strftime("%b %d %H:%M:%S")
print("\n*** program start time:", current_time_str, "******")


# ********************************************************************
# ******** open file one log line at a time **************************
def openLogFile(path):
    with open(path) as log_file:
        for log_entry in log_file:
            yield log_entry

# Initialize a count for the total number of entries
total_entries_count = 0

# Create a list to store log entries as dictionaries
log_entries = []

# ********************************************************************
# *** Define a function to parse the log entries  ********************
path = "part2.log"
log_file = openLogFile(path) # Read and parse log entries into dictionaries

for log_entry in log_file:
    total_entries_count += 1  # Increment the count for each entry

    # Define regex pattern to extract log entry fields
    pattern = r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\w+) (\w+)\((\w+)\)\[(\d+)\]: (.+)'

    # Use re.match to extract fields from the log entry
    match = re.match(pattern, log_entry)

    if match:
        timestamp, hostname, component, action, pid, message = match.groups()
        log_entry_dict = {
            "original_timestamp": timestamp,
            "current_timestamp": current_time_str,
            "hostname": hostname,
            "component": component,
            "action": action,
            "pid": pid,
            "message": message
        }
        log_entries.append(log_entry_dict)


# ********************************************************************
# ****** Get the top 3 most common components ************************
# Count the occurrences of 'component' components
component_counter = Counter(entry['component'] for entry in log_entries)

# Find the top 3 most common 'component' components
top_3_components = component_counter.most_common(3)


# parsing time for working hours vs after hours
def parse_log_entry(log_entry):
    pattern = r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\w+) (\w+)\((\w+)\)\[(\d+)\]: (.+)'
    match = re.match(pattern, log_entry)
    if match:
        timestamp, hostname, component, action, pid, message = match.groups()
        return {
            "original_timestamp": timestamp,
            "component": component,
        }
    else:
        return None

# Define a function to classify time as working hours or after hours
def classify_time(timestamp):
    hour = timestamp.hour
    if 9 <= hour <= 17:
        return "Working Hours"
    else:
        return "After Hours"

# ********************************************************************
# *****************  Create a plot  **********************************
def plot_component_usage(log_entries):
    component_counter = Counter(entry['component'] for entry in log_entries)
    working_hours_counter = Counter()
    after_hours_counter = Counter()

    for entry in log_entries:
        timestamp = datetime.datetime.strptime(entry["original_timestamp"], "%b %d %H:%M:%S")
        time_category = classify_time(timestamp)
        component = entry["component"]

        if time_category == "Working Hours":
            working_hours_counter.update([component])
        else:
            after_hours_counter.update([component])

    top_3_components = component_counter.most_common(3)
   
    plt.figure(figsize=(12, 6))

    for i, (component, count) in enumerate(top_3_components, 1):
        plt.subplot(3, 1, i)
        plt.bar(
            [f"{component} - Working Hours ( {working_hours_counter[component]})", f"{component} - After Hours ({after_hours_counter[component]})"],
            [working_hours_counter[component], after_hours_counter[component]]
        )
        plt.title(f"Usage of {component} component during Working Hours and After Hours")
        plt.ylim(0, 300)  # Set the y-axis limits to 0-300

    plt.tight_layout()
    plt.show()


# ********************************************************************
# *********************  print  **************************************
# ********************************************************************
print("\n\n* * * * * * * LOG FILE ANALYZER * * * * * * *\n\n")
print(f"for filename {path}")
print("Total number of log entries:", total_entries_count,"\n")
print("Top 3 most common components:")
for component, count in top_3_components:
    print(f"Component: {component}, Count: {count}")
print("\nSee visualized data in external Python window\n\n*** program end time:", current_time_str,"********\n")

# Call the function to create and display the plot
plot_component_usage(log_entries)


# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# component descriptions  component descriptions  component description
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# component: sshf (Secure Shell Daemon)--------------------------------
# ---------------------------------------------------------------------
# responsible for managing SSH connections on the system
# in part2.log, some sshd components mark failed authentication
# for a user trying to sign in using SSH
# the details include the username, IP address (rhost), and auth status
#
# ---------------------------------------------------------------------
# component: su (Substitude User) -------------------------------------
# ---------------------------------------------------------------------
# command used to switch to a different account
# often with superuser priviledges. 
# in part2.log, some su components mark
# a session (initiated by the user) was closed. 
# related to account switching

# ---------------------------------------------------------------------
# component: gdm (GNOME Display Manager) ------------------------------
# ---------------------------------------------------------------------
# repsonsible for managing the graphical login screen 
# in the GNOME desktop environment. 
# in part2.log, some gdm components relate to 
# the auth process for users trying to log into
# the graphical interface, includes auth status
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------

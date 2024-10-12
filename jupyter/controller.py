import paramiko
import ipaddress
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import ipywidgets as widgets
from IPython.display import display, clear_output, HTML
import matplotlib.pyplot as plt
import logging
from collections import deque
import time
import socket

ONLINE_IPS_FILE = "online_ips.json"

# Configure logging
class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.append(self.format(record))
        if len(self.log_queue) > 20:
            self.log_queue.popleft()

log_queue = deque(maxlen=20)
queue_handler = QueueHandler(log_queue)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[queue_handler])
logger = logging.getLogger(__name__)

# Disable Paramiko logging
logging.getLogger("paramiko").setLevel(logging.WARNING)

def is_ip_online(ip):
    try:
        socket.setdefaulttimeout(1)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((ip, 22))
        return True
    except socket.error:
        return False

def test_ssh_connection(ip, username, password):
    try:
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(str(ip), username=username, password=password, timeout=2, banner_timeout=2)
        return True
    except Exception:
        return False

def check_single_ip(args):
    ip, username, password = args
    if is_ip_online(ip) and test_ssh_connection(ip, username, password):
        return str(ip)
    return None

def update_output(pbar, log_output, detailed_results):
    log_output.clear_output(wait=True)
    with log_output:
        print("Detailed Results (last 20):")
        for result in list(detailed_results)[-20:]:
            print(result)

def scan_ip_range(start_ip, end_ip, username, password, max_workers=50, output_area=None):
    logger.info(f"Starting IP range scan from {start_ip} to {end_ip}")
    ip_range = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip),
                                                      ipaddress.IPv4Address(end_ip)))
    all_ips = [ip for block in ip_range for ip in block]
    
    args = [(str(ip), username, password) for ip in all_ips]
    
    online_ips = []
    detailed_results = deque(maxlen=20)
    start_time = time.time()

    progress_bar = widgets.IntProgress(
        value=0,
        min=0,
        max=len(args),
        description='Scanning:',
        bar_style='info',
        orientation='horizontal'
    )
    log_output = widgets.Output()

    display(progress_bar, log_output)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check_single_ip, arg): arg for arg in args}
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                online_ips.append(result)
                detailed_results.append(f"Found online IP: {result}")
            progress_bar.value += 1
            if progress_bar.value % 10 == 0 or progress_bar.value == len(args):
                update_output(progress_bar, log_output, detailed_results)
    
    scan_duration = time.time() - start_time
    logger.info(f"Scan completed in {scan_duration:.2f} seconds")
    logger.info(f"Found {len(online_ips)} online IPs")
    logger.info(f"Saving online IPs to {ONLINE_IPS_FILE}")
    with open(ONLINE_IPS_FILE, 'w') as f:
        json.dump(online_ips, f)
    
    update_output(progress_bar, log_output, detailed_results)
    return online_ips

def load_online_ips():
    logger.info(f"Attempting to load online IPs from {ONLINE_IPS_FILE}")
    if os.path.exists(ONLINE_IPS_FILE):
        with open(ONLINE_IPS_FILE, 'r') as f:
            online_ips = json.load(f)
            logger.info(f"Loaded {len(online_ips)} online IPs")
            return online_ips
    logger.info("No saved online IPs found")
    return []

def run_command(args):
    ip, username, password, command = args
    try:
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=5, banner_timeout=5)
            stdin, stdout, stderr = ssh.exec_command(command, timeout=10)
            result = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            if error:
                return ip, 'partial_success', f"Result: {result}\nError: {error}"
            return ip, 'success', result
    except Exception as e:
        return ip, 'failed', str(e)

def track_success_rate(results):
    total = len(results)
    success_count = sum(1 for ip, status, _ in results if status == 'success')
    partial_success_count = sum(1 for ip, status, _ in results if status == 'partial_success')
    failure_count = total - success_count - partial_success_count
    
    print(f"Total Machines: {total}")
    print(f"Successes: {success_count}")
    print(f"Partial Successes: {partial_success_count}")
    print(f"Failures: {failure_count}")
    
    plt.figure(figsize=(10, 6))
    sizes = [success_count, partial_success_count, failure_count]
    labels = ['Success', 'Partial Success', 'Failure']
    colors = ['#4CAF50', '#FFC107', '#F44336']
    
    plt.pie([size if size > 0 else 0.00001 for size in sizes], 
            labels=[label if sizes[i] > 0 else '' for i, label in enumerate(labels)], 
            autopct=lambda pct: f'{pct:.1f}%' if pct > 0 else '',
            colors=colors,
            startangle=90)
    plt.title('Command Execution Results')
    plt.axis('equal')
    plt.tight_layout()
    plt.show()

def execute_on_online_ips(username, password, command, max_workers=50, output_area=None):
    logger.info("Starting command execution on online IPs")
    online_ips = load_online_ips()
    if not online_ips:
        print("No online IPs found. Please scan the range first.")
        return

    logger.info(f"Preparing to execute command on {len(online_ips)} IPs")
    args = [(ip, username, password, command) for ip in online_ips]
    
    results = []
    detailed_results = deque(maxlen=20)
    start_time = time.time()

    progress_bar = widgets.IntProgress(
        value=0,
        min=0,
        max=len(args),
        description='Executing:',
        bar_style='info',
        orientation='horizontal'
    )
    log_output = widgets.Output()

    display(progress_bar, log_output)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(run_command, arg): arg for arg in args}
        for future in as_completed(future_to_ip):
            ip, status, message = future.result()
            results.append((ip, status, message))
            detailed_results.append(f"{ip}: {status} - {message[:100]}...")  # Truncate long messages
            progress_bar.value += 1
            if progress_bar.value % 5 == 0 or progress_bar.value == len(args):
                update_output(progress_bar, log_output, detailed_results)
    
    execution_duration = time.time() - start_time
    logger.info(f"Command execution completed in {execution_duration:.2f} seconds")
    
    return results

# Function to get VM IP from host IP
def get_vm_ip(host_ip):
    ip_parts = host_ip.split('.')
    ip_parts[2] = '5' + ip_parts[2][1:]
    return '.'.join(ip_parts)

# Function to execute command on VMs
def execute_on_vms(username, password, command, max_workers=50, output_area=None):
    logger.info("Starting command execution on VMs")
    host_ips = load_online_ips()
    if not host_ips:
        print("No host IPs found. Please scan the range first.")
        return

    vm_ips = [get_vm_ip(host_ip) for host_ip in host_ips]
    logger.info(f"Preparing to execute command on {len(vm_ips)} VMs")
    args = [(ip, username, password, command) for ip in vm_ips]
    
    results = []
    detailed_results = deque(maxlen=20)
    start_time = time.time()

    progress_bar = widgets.IntProgress(
        value=0,
        min=0,
        max=len(args),
        description='Executing on VMs:',
        bar_style='info',
        orientation='horizontal'
    )
    log_output = widgets.Output()

    display(progress_bar, log_output)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(run_command, arg): arg for arg in args}
        for future in as_completed(future_to_ip):
            ip, status, message = future.result()
            results.append((ip, status, message))
            detailed_results.append(f"{ip}: {status} - {message[:100]}...")  # Truncate long messages
            progress_bar.value += 1
            if progress_bar.value % 5 == 0 or progress_bar.value == len(args):
                update_output(progress_bar, log_output, detailed_results)
    
    execution_duration = time.time() - start_time
    logger.info(f"VM command execution completed in {execution_duration:.2f} seconds")
    
    return results

# UI Elements
start_ip_widget = widgets.Text(value='172.16.10.0', description="Start IP:")
end_ip_widget = widgets.Text(value='172.16.20.100', description="End IP:")
username_widget = widgets.Text(value='root', description="Username:")
password_widget = widgets.Password(value='password', description="Password:")
command_widget = widgets.Text(description="Command:", value='uname -a')
max_workers_widget = widgets.IntSlider(value=50, min=1, max=100, description='Max Workers:', continuous_update=False)

scan_button = widgets.Button(description="Scan IP Range", button_style='primary')
execute_button = widgets.Button(description="Run on P", button_style='success')
execute_vm_button = widgets.Button(description="Run Commands on VMs", button_style='warning')
output_area = widgets.Output()

def on_scan_button_clicked(b):
    start_ip = start_ip_widget.value
    end_ip = end_ip_widget.value
    username = username_widget.value
    password = password_widget.value
    max_workers = max_workers_widget.value
    
    with output_area:
        clear_output(wait=True)
        online_ips = scan_ip_range(start_ip, end_ip, username, password, max_workers, output_area)
        
        print(f"\nScan completed. Found {len(online_ips)} online IPs")
        
        print("\nOnline IPs per Subnet:")
        subnets = {}
        for ip in online_ips:
            subnet = '.'.join(ip.split('.')[:3])
            subnets[subnet] = subnets.get(subnet, 0) + 1
        
        plt.figure(figsize=(12, 6))
        bars = plt.bar(subnets.keys(), subnets.values())
        plt.title('Online IPs per Subnet')
        plt.xlabel('Subnet')
        plt.ylabel('Number of Online IPs')
        plt.xticks(rotation=45, ha='right')
        
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height}',
                     ha='center', va='bottom')
        
        plt.tight_layout()
        plt.show()

def on_execute_button_clicked(b):
    username = username_widget.value
    password = password_widget.value
    command = command_widget.value
    max_workers = max_workers_widget.value
    
    with output_area:
        clear_output(wait=True)
        results = execute_on_online_ips(username, password, command, max_workers, output_area)
        
        print("\nCommand execution on hosts completed")
        
        print("\nExecution Results:")
        track_success_rate(results)

def on_execute_vm_button_clicked(b):
    username = username_widget.value
    password = password_widget.value
    command = command_widget.value
    max_workers = max_workers_widget.value
    
    with output_area:
        clear_output(wait=True)
        results = execute_on_vms(username, password, command, max_workers, output_area)
        
        print("\nCommand execution on VMs completed")
        
        print("\nExecution Results:")
        track_success_rate(results)

# Arrange the UI
ui = widgets.VBox([
    widgets.HBox([scan_button, execute_button, execute_vm_button]),
    widgets.HBox([start_ip_widget, end_ip_widget]),
    widgets.HBox([username_widget, password_widget]),
    widgets.HBox([command_widget, max_workers_widget]),
    output_area
])

# Connect button click events
scan_button.on_click(on_scan_button_clicked)
execute_button.on_click(on_execute_button_clicked)
execute_vm_button.on_click(on_execute_vm_button_clicked)

# Display the UI
display(ui)

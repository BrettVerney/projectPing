import ipaddress
import datetime
import argparse
from tqdm import tqdm
import concurrent.futures
from pythonping import ping as pythonping

# Set retries and timeout values directly in the script
RETRIES = 1
TIMEOUT = 1000  # Timeout in milliseconds

def ping(host):
    for _ in range(RETRIES):
        try:
            response = pythonping(host, count=1, timeout=TIMEOUT / 1000)
            if response.success():
                return True, host
        except Exception:
            pass
    return False, host

def process_host(input_host):
    ip_list = []
    try:
        # Check if it's a CIDR notation
        if '/' in input_host:
            network = ipaddress.ip_network(input_host.strip(), strict=False)
            ip_list.extend([str(ip) for ip in network.hosts()])
        elif '-' in input_host:
            # Handle IP range
            start_ip_str, end_ip_str = input_host.split('-')
            start_ip = ipaddress.IPv4Address(start_ip_str.strip())
            end_ip = ipaddress.IPv4Address(end_ip_str.strip())
            if start_ip > end_ip:
                print(f"Invalid IP range: '{input_host}'. Start IP is greater than end IP. Skipping.")
            else:
                ip_range = range(int(start_ip), int(end_ip) + 1)
                ip_list.extend([str(ipaddress.IPv4Address(ip)) for ip in ip_range])
        else:
            # Handle single IP
            ipaddress.IPv4Address(input_host.strip())
            ip_list.append(input_host.strip())
    except ValueError as ve:
        print(f"Invalid IP address or range '{input_host}': {ve}. Skipping.")
    return ip_list

def read_hosts_from_file(filename):
    hosts = []
    try:
        with open(filename, 'r') as file:
            hosts = [line.split(',')[0].strip() for line in file]
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    except IOError as e:
        print(f"Error reading file: {e}")
    return hosts

def compare_and_report_changes(current_results, comparison_file):
    try:
        with open(comparison_file, 'r') as file:
            previous_results = {
                line.split(',')[0]: line.strip().endswith('True') for line in file.readlines()
            }
        
        changes_detected = False
        for ip, is_pingable in current_results.items():
            prev_pingable = previous_results.get(ip, None)
            if prev_pingable is not None and prev_pingable != is_pingable:
                changes_detected = True
                if is_pingable:
                    print(f"{ip} wasn't pingable previously, but now is.")
                else:
                    print(f"{ip} was pingable previously, but now is not.")
        
        if not changes_detected:
            print("No changes in pingability.")
    except FileNotFoundError:
        print(f"Comparison file '{comparison_file}' not found.")

def write_results_to_file(results):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"ping_results_{timestamp}.txt"
    def sort_key(item):
        try:
            return ipaddress.ip_address(item[0])
        except ValueError:
            return float('inf')  # Invalid IPs are sorted last
    with open(filename, 'w') as file:
        for ip, success in sorted(results.items(), key=sort_key):
            file.write(f"{ip},{success}\n")
    print(f"Results written to {filename}")

def main(ips=None, comparison_file=None, max_workers=64):
    current_results = {}
    hosts = []
    pingable_hosts = []

    if comparison_file and not ips:
        hosts = read_hosts_from_file(comparison_file)
    elif ips:
        for ip_input in ips.split(','):
            ip_input = ip_input.strip()
            ip_list = process_host(ip_input)
            # Removed redundant message
            hosts.extend(ip_list)
    
    if not hosts:
        print("No valid IPs specified. Exiting.")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping, host): host for host in hosts}
        with tqdm(total=len(hosts), desc="Pinging devices", unit="device", miniters=1, mininterval=0.1) as progress_bar:
            for future in concurrent.futures.as_completed(futures):
                success, ip = future.result()
                current_results[ip] = success
                if success:
                    pingable_hosts.append(ip)
                progress_bar.update(1)

    write_results_to_file(current_results)  # Always write the results to a file
    
    # Print pingable IPs only after progress bar completes and when -i is specified
    if ips:
        for ip in pingable_hosts:
            print(f"{ip} is pingable")
    
    if comparison_file:  # Compare and report changes only when -c is specified
        compare_and_report_changes(current_results, comparison_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ping a list of hosts and optionally compare with previous results.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ips", help="List of IPs or subnets to ping, separated by commas.")
    group.add_argument("-c", "--comparison_file", help="Path to a file for comparison, pings devices listed in the file.")

    args = parser.parse_args()
    main(args.ips, args.comparison_file, max_workers=64)

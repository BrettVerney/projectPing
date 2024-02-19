import subprocess
import ipaddress
import datetime
import argparse
from tqdm import tqdm
import concurrent.futures

# Set retries and timeout values directly in the script
RETRIES = 1
TIMEOUT = 1000  # Timeout in milliseconds

def ping(host):
    command = ['ping', '-n', '1', '-w', str(TIMEOUT), host]
    for _ in range(RETRIES):
        try:
            subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return True, host
        except subprocess.CalledProcessError:
            continue
    return False, host

def process_host(input_host):
    try:
        network = ipaddress.ip_network(input_host, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        if '-' in input_host:
            start_ip, end_ip = input_host.split('-')
            ip_range = range(int(ipaddress.IPv4Address(start_ip.strip())), int(ipaddress.IPv4Address(end_ip.strip())) + 1)
            return [str(ipaddress.IPv4Address(ip)) for ip in ip_range]
        else:
            return [input_host.strip()]

def read_hosts_from_file(filename):
    hosts = []
    try:
        with open(filename, 'r') as file:
            hosts = [line.split(',')[0] for line in file]
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    except IOError as e:
        print(f"Error reading file: {e}")
    return hosts

def compare_and_report_changes(current_results, comparison_file):
    try:
        with open(comparison_file, 'r') as file:
            previous_results = {line.split(',')[0]: line.strip().endswith('True') for line in file.readlines()}
        
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
    with open(filename, 'w') as file:
        for ip, success in sorted(results.items(), key=lambda item: ipaddress.ip_address(item[0])):
            file.write(f"{ip},{success}\n")
    print(f"Results written to {filename}")

def main(ips=None, comparison_file=None, max_workers=64):
    current_results = {}
    hosts = []
    pingable_hosts = []

    if comparison_file and not ips:
        hosts = read_hosts_from_file(comparison_file)
    elif ips:
        for ip in ips.split(','):
            hosts.extend(process_host(ip.strip()))
    
    if not hosts:
        print("No IPs specified. Exiting.")
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

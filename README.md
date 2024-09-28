# projectPing
Compare ping results of hosts before and after an infrastructure upgrade.

**projectPing** is a Python tool designed to ping a list of hosts to check their availability. It can accept input in various formats, including individual IP addresses, CIDR notation for subnets, or ranges of IP addresses, and can compare the current ping results against previous results to identify changes in host availability.

## Installation

Ensure you have Python installed on your system. This tool has been tested with Python 3.8 and above.

Install the required dependencies using pip:

```pip install pythonping tqdm```

## Usage
projectPing can be used with the following options:

```-i``` to specify a list of IPs or subnets to ping.<br>
```-c``` to specify a comparison file to compare current results with.<br>

### Examples
Ping a list of individual IPs:<br>
```python projectPing.py -i "192.168.1.1,192.168.1.2"```<br>

Ping a range of IPs:<br>
```python projectPing.py -i "192.168.1.1-192.168.1.5"```

Ping a subnet using CIDR notation:<br>
```python projectPing.py -i "192.168.1.0/24"```

Compare current ping results with a previous run:<br>
```python projectPing.py -c "ping_results_previous.txt"```

### Output
The tool outputs the ping results to a timestamped text file named ping_results_YYYY-MM-DD_HH-MM-SS.txt. When comparing results, it also prints changes in pingability to the console.

## Contributing
Contributions to projectPing are welcome! Feel free to submit pull requests or open issues for bugs and feature requests.

## License
projectPing is distributed under the MIT License. See LICENSE file for more information.


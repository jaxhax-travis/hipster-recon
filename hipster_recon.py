#!/usr/bin/env python3
"""
Program: hipster_recon.py

Date: 01/27/2022

Author: Travis Phillips

Purpose: A pre-engagement script for confirming scope. Features include:

         * Converts a CIDR notation IP into a range/list of IP addresses,
            * Can dump a raw list and exit for creating target list.
         * Performs ASIN WHOIS lookup on one of the IPs to get org
             name information and subnet records
         * Optionally, runs a scan looking for SSL ports (443, 8443) and
             extracts issuer, common name, and alternative names from
             their certs.
"""
import sys
import argparse
import ipaddress
import socket
import threading
import ssl
from queue import Queue
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

class PortScanner:
    """ A port scanner class for multi-thread port scanning. """
    def __init__(self, hosts: list, ports: list, verbose=False, timeout=1) -> None:
        """ Initalize the port scanner class. """
        self.hosts = hosts
        self.ports = ports
        self.verbose = verbose
        self.timeout = timeout
        self.results = {}
        self.queue = Queue()

    def _print(self, message: str) -> None:
        """ Verbose print function for scanning. """
        if self.verbose:
            print(message)

    def scan_host(self, host: str) -> None:
        """
        Thread job that will scan the host for self.ports. If an open
        port is found, then it will be added to the dictionary
        self.results[host], which is a list of open ports.
        """
        for port in self.ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(self.timeout)
            result = sock.connect_ex((host,port))
            if result == 0:
                if host not in self.results:
                    self.results[host] = []
                self._print(f"    [*] {host}:{port} is open!")
                self.results[host].append(port)
                sock.close()

    def _worker(self) -> None:
        """ Thread worker function. Will pull a host from queue and run the scan. """
        while True:
            # Get a host from the queue
            worker = self.queue.get()
            self.scan_host(worker)
            self.queue.task_done()

    def run(self, nthreads=100) -> None:
        """ Run the port scanner. This is a blocking call until scan is complete. """
        print(" [*] Scanning for open SSL ports...")
        for _x in range(nthreads):
            thread = threading.Thread(target=self._worker)
            thread.daemon = True
            thread.start()

        for host in self.hosts:
            self.queue.put(host)

        # block until all tasks are done
        self.queue.join()
        self._print(" [*] Scan Complete!\n")

########################################################################
#                     TABLE DRAWING FUNCTIONS
########################################################################
def row_has_lists(row: list) -> bool:
    """ Returns if the dataset has list or not. """
    for item in row:
        if isinstance(item, list):
            return True
    return False

def normalize_dataset(dataset: list) -> list:
    """
    Converts all row cells into lists containing the same
    number of elements.
    """
    new_dataset = []
    for row in dataset:
        new_row = []
        if row_has_lists(row):
            max_array_count = get_max_elements_in_row(row)
            for item in row:
                if isinstance(item, str):
                    new_item = [item]
                    for _idx in range(max_array_count-1):
                        new_item.append("")
                else:
                    new_item = item.copy()
                    while len(new_item) < max_array_count:
                        new_item.append("")
                new_row.append(new_item)
        else:
            for item in row:
                new_row.append([item])
        new_dataset.append(new_row)
    return new_dataset

def get_max_elements_in_row(row: list) -> int:
    """
    Loops through the dataset and gets the max elements in a list if
    one is found in the list or 1 if all strings.
    """
    max_array_count = 0

    # get the max height of the cells.
    for item in row:
        if isinstance(item, list) and len(item) > max_array_count:
            max_array_count = len(item)
        elif isinstance(item, str) and max_array_count == 0:
            max_array_count = 1
    return max_array_count

def get_max_cell_widths(dataset: list) -> list:
    """ get the max width of cells. """
    max_widths = [0] * len(dataset[0])
    for row in dataset:
        for idx, cell in enumerate(row):
            for item in cell:
                if len(item) > max_widths[idx]:
                    max_widths[idx] = len(item)
    return max_widths

def print_table_header(title: str, max_lengths: list) -> None:
    """ Draws an ASCII table to represent a dataset. """
    total_length = sum(max_lengths) + (2 * len(max_lengths)) + (len(max_lengths)-1)
    print("")
    row_sep(max_lengths, start="┌", sep='─', end="┐")
    print(f"│{title.center(total_length)}│")
    row_sep(max_lengths, sep="┬")

def row_sep(max_lengths: list, start="├", sep="┼", end="┤") -> None:
    """ split row draw function. """
    buf = start
    for length in max_lengths:
        buf += f"{'─'*(length+2)}{sep}"
    buf = buf[:-1] + f"{end}"
    print(buf)

def print_row(max_lengths: list, row: list, center=False) -> None:
    """ Print the data row. """
    max_array_count = get_max_elements_in_row(row)
    buf = ""
    for cell_idx in range(max_array_count):
        if cell_idx == 0:
            buf += "│"
        else:
            buf += "\n│"
        for row_idx, _cell in enumerate(row):
            if center:
                buf += f" {row[row_idx][cell_idx].center(max_lengths[row_idx])} │"
            else:
                buf += f" {row[row_idx][cell_idx].ljust(max_lengths[row_idx])} │"
    print(buf)

def draw_table(title: str, dataset: list) -> None:
    """ Draws an ASCII table to represent a dataset. """

    normalized_dataset = normalize_dataset(dataset)

    max_lengths = get_max_cell_widths(normalized_dataset)

    print_table_header(title, max_lengths)
    for idx, row in enumerate(normalized_dataset):
        # Print the row
        if idx == 0:
            # If idx is first row, it should be a table headers.
            print_row(max_lengths, row, center=True)
        else:
            # This is a normal row.
            print_row(max_lengths, row)

        # Print a row seperator.
        if idx == len(dataset)-1:
            row_sep(max_lengths, start="└", sep='┴', end="┘")
        else:
            row_sep(max_lengths)

    print("")

########################################################################
#                 WHOIS AND CERT ENUMERATION FUNCTIONS
########################################################################
def extract_arin_org_name(record: dict) -> str:
    """
    Attempts to extract the customer name or org name from the record. If
    this isn't possible, it will return an empty string.
    """
    org_name = ""
    if 'customerRef' in record and '@name' in record['customerRef']:
        org_name = record['customerRef']['@name']
        if '@handle' in record['customerRef']:
            org_name += f" ({record['customerRef']['@handle']})"
    elif 'orgRef' in record:
        org_name = record['orgRef']['@name']
    return org_name

def extract_arin_netblocks(netblock: dict) -> str:
    """
    Attempts to extract the customer name or org name from the record. If
    this isn't possible, it will return an empty string.
    """
    if isinstance(netblock, list):
        start_ip = []
        end_ip = []
        cidr = []
        for row in netblock:
            start_ip.append(row['startAddress']['$'])
            end_ip.append(row['endAddress']['$'])
            cidr.append(f"{row['startAddress']['$']}/{row['cidrLength']['$']}")
    else:
        start_ip = netblock['startAddress']['$']
        end_ip = netblock['endAddress']['$']
        cidr = f"{start_ip}/{netblock['cidrLength']['$']}"
    return (start_ip, end_ip, cidr)

def get_arin_info(ip_addr: str) -> None:
    """ Query the ARIN for IP information. """
    records = [["CIDR", "Start", "End", "Organization"]]
    url = f"http://whois.arin.net/rest/nets;q={ip_addr}?showDetails=true&showARIN=true"
    headers = {"Accept": "application/json"}
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        data = res.json()['nets']['net']
        if isinstance(data, dict):
            org_name = extract_arin_org_name(record)
            netblock = record['netBlocks']['netBlock']
            start_ip, end_ip, cidr = extract_arin_netblocks(netblock)
            records.append([cidr, start_ip, end_ip, org_name])
        else:
            for record in data:
                org_name = extract_arin_org_name(record)
                netblock = record['netBlocks']['netBlock']
                start_ip, end_ip, cidr = extract_arin_netblocks(netblock)
                records.append([cidr, start_ip, end_ip, org_name])
    draw_table("ARIN Records", records)

def get_ssl_cert(host: str, port: int) -> x509.Certificate:
    """ Connect and get cert information. """
    try:
        ssl_info = ssl.get_server_certificate((host, port))
        cert = x509.load_pem_x509_certificate(ssl_info.encode('utf-8'))
        return cert
    except ConnectionResetError:
        return None

def get_common_name(cert: x509.Certificate) -> str:
    """ Get the common name from a X509 cert. """
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_alternatives_names(cert: x509.Certificate) -> list:
    """ Get the alternative names as a list from a X509 cert. """
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert: x509.Certificate) -> str:
    """ Get the alternative names as a list from a X509 cert. """
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

########################################################################
#                 ARG PARSER & MISC FUNCTIONS
########################################################################
def print_range(ip_range: list) -> None:
    """ Print the IP range. """
    for ip_addr in ip_range:
        print(f"{ip_addr}")

def parse_args() -> None:
    """ Parse the arguments or show help. """
    desc = "  Converts a CIDR notation IP into a range/list of IP addresses,\n"
    desc += "  performs a ASIN WHOIS lookup on one of the IPs to get org name,\n"
    desc += "  and optionally runs a port scan for 443/8443 looking for SSL ports\n"
    desc += "  and extracts common and alt names and issuers from their certs."
    epilog = "\n\nNOTES:\n\t---===[ Network Traffic ]===---\n"
    epilog += "  - IP Range listing requires no network traffic.\n"
    epilog += "  - ARIN will query API at https://whois.arin.net/.\n"
    epilog += "  - SSL Scan will send traffic to target subnet:\n"
    epilog += "      - Connect port scan against TCP ports 443 & 8443.\n"
    epilog += "      - Connect to ports for certificate extraction.\n\n"
    epilog += "\n\n\t---===[ About the Name ]===---\n"
    epilog += " This tool is called Hipster Recon because it does recon on CIDR...\n"
    epilog += " Remember: A pun is just a joke that isn't fully groan.\n\n"
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=desc, epilog=epilog)
    parser.add_argument('--list', '-l',
                        help="Dump a raw list of the CIDR IP range & exit. \
                            Useful for target list files",
                        action='store_true')
    parser.add_argument('--sslscan', '-s',
                        help='Enable SSL Scan of the subnet',
                        action='store_true')
    parser.add_argument('--timeout', default=1, type=int,
                        help="Socket timeout for SSL port scanning.")
    parser.add_argument('--verbose', '-v',
                        help='Allows more output during SSL Scan',
                        action='store_true')
    parser.add_argument('CIDR_IP',
                        help='CIDR Notation IP Subnet or single IP [Hostname not permitted]')

    # If no arguments where provided, print help.
    if len(sys.argv) == 1:
        parser.print_help()
        return None

    # Parse arguments.
    args = parser.parse_args()
    return args

########################################################################
#                           MAIN LOGIC
########################################################################
def main() -> int:
    """ Main Application Logic. """
    args = parse_args()
    if not args:
        return 1

    # Extract the IP range for the CIDR into a list
    ip_range = [str(ip) for ip in ipaddress.IPv4Network(args.CIDR_IP, False).hosts()]

    # Print the IP range as a list or dash range to the user.
    if args.list:
        print_range(ip_range)
        return 0
    print(f"\n [*] IP Range: {ip_range[0]} - {ip_range[-1]}")

    # Query ASIN and dump a table of the Netblock records.
    get_arin_info(ip_range[0])

    if args.sslscan:
        # Scan for open SSL ports
        ssl_ports = [443, 8443]
        scanner = PortScanner(ip_range, ssl_ports, verbose=args.verbose,
                              timeout=args.timeout)
        scanner.run()

        # Extract SSL Certs from live hosts
        certs = [["Host/Port", "Issuer", "Common Name", "Alt. Names"]]
        print(" [*] Grabbing SSL Certs...")
        for host, ports in scanner.results.items():
            for port in ports:
                cert = get_ssl_cert(host, port)
                if cert:
                    certs.append([f"{host}:{port}",
                                  get_issuer(cert),
                                  get_common_name(cert),
                                  get_alternatives_names(cert)])
            print(f" [*] {len(certs)-1} SSL certs obtained!")
        if len(certs) > 1:
            draw_table("SSL Certificates", certs)
    return 0

if __name__ == "__main__":
    sys.exit(main())

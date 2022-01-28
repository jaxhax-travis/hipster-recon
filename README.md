# Hipster Recon
A pre-engagement tool for pententration testers performing light recon on CIDR ranges.  It's called Hipster Recon because it does recon on CIDR.  Remember: a pun is a joke that isn't fully groan.

# Overview
Hipster Recon is a tool for performing light recon on CIDR notation IP ranges. This tool was designed to help with pre-engagement recon to verify CIDR subnets.  This tool can assist with the following task:

 * **Show the IP range of the CIDR:**
   * This can be done as a 127.0.0.1-255 range
   * Or dump a list of individual IP address and exit, which can be useful for dumping to target files.
 * **Performs ASIN WHOIS lookup on one of the IPs in the CIDR range to obtain all subnet records:**
   * CIDR Notation
   * Start and End Range
   * Organization Name
 * **Optionally: Perform a multi-threaded scan for SSL Ports (443,8443) and extract SSL certificates information:**
   * Useful since common and alternative names are contained in certificates and can help verify subnet owner.

The information above is useful for validating the client-provided scope in fact belongs to the client and is a good pre-flight check before moving forward with the penetration test when performing external pentration test. 

# Basic usage:
**Help Screen:**
```
$ python3 ./hipster_recon.py --help
usage: hipster_recon.py [-h] [--list] [--sslscan] [--timeout TIMEOUT] [--verbose] CIDR_IP

  Converts a CIDR notation IP into a range/list of IP addresses,
  performs a ASIN WHOIS lookup on one of the IPs to get org name,
  and optionally runs a port scan for 443/8443 looking for SSL ports
  and extracts common and alt names and issuers from their certs.

positional arguments:
  CIDR_IP            CIDR Notation IP Subnet or single IP [Hostname not permitted]

optional arguments:
  -h, --help         show this help message and exit
  --list, -l         Dump a raw list of the CIDR IP range & exit. Useful for target list files
  --sslscan, -s      Enable SSL Scan of the subnet
  --timeout TIMEOUT  Socket timeout for SSL port scanning.
  --verbose, -v      Allows more output during SSL Scan

NOTES:
        ---===[ Network Traffic ]===---
  - IP Range listing requires no network traffic.
  - ARIN will query API at https://whois.arin.net/.
  - SSL Scan will send traffic to target subnet:
      - Connect port scan against TCP ports 443 & 8443.
      - Connect to ports for certificate extraction.

        ---===[ About the Name ]===---
 This tool is called Hipster Recon because it does recon on CIDR...
 Remember: A pun is just a joke that isn't fully groan.
```


**Get IP Range and ARIN Information of CIDR Subnet:**
```
$ python3 ./hipster_recon.py 192.168.1.0/24

 [*] IP Range: 192.168.1.1 - 192.168.1.254

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                       ARIN Records                                       │
├────────────────┬─────────────┬─────────────────┬─────────────────────────────────────────┤
│      CIDR      │    Start    │       End       │               Organization              │
├────────────────┼─────────────┼─────────────────┼─────────────────────────────────────────┤
│ 192.0.0.0/8    │ 192.0.0.0   │ 192.255.255.255 │ Various Registries (Maintained by ARIN) │
├────────────────┼─────────────┼─────────────────┼─────────────────────────────────────────┤
│ 192.168.0.0/16 │ 192.168.0.0 │ 192.168.255.255 │ Internet Assigned Numbers Authority     │
└────────────────┴─────────────┴─────────────────┴─────────────────────────────────────────┘
```


**Dump IP List of CIDR Subnet:**
```
$ python3 ./hipster_recon.py --list 192.168.1.129/28 | tee targets.txt
192.168.1.129
192.168.1.130
192.168.1.131
192.168.1.132
192.168.1.133
192.168.1.134
192.168.1.135
192.168.1.136
192.168.1.137
192.168.1.138
192.168.1.139
192.168.1.140
192.168.1.141
192.168.1.142
```

**Dump IP Range of CIDR Subnet, Scan SSL Ports and Get Certificate Info For example.com:**
```
$ python3 ./hipster_recon.py --sslscan 93.184.216.34
 [*] IP Range: 93.184.216.34 - 93.184.216.34

┌───────────────────────────────────────────────────────────────────────────┐
│                                ARIN Records                               │
├────────────┬──────────┬────────────────┬──────────────────────────────────┤
│    CIDR    │  Start   │      End       │           Organization           │
├────────────┼──────────┼────────────────┼──────────────────────────────────┤
│ 93.0.0.0/8 │ 93.0.0.0 │ 93.255.255.255 │ RIPE Network Coordination Centre │
└────────────┴──────────┴────────────────┴──────────────────────────────────┘

 [*] Scanning for open SSL ports...
 [*] Grabbing SSL Certs...
 [*] 1 SSL certs obtained!

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                     SSL Certificates                                     │
├───────────────────┬──────────────────────────────────┬─────────────────┬─────────────────┤
│     Host/Port     │              Issuer              │   Common Name   │    Alt. Names   │
├───────────────────┼──────────────────────────────────┼─────────────────┼─────────────────┤
│ 93.184.216.34:443 │ DigiCert TLS RSA SHA256 2020 CA1 │ www.example.org │ www.example.org │
│                   │                                  │                 │ example.net     │
│                   │                                  │                 │ example.edu     │
│                   │                                  │                 │ example.com     │
│                   │                                  │                 │ example.org     │
│                   │                                  │                 │ www.example.com │
│                   │                                  │                 │ www.example.edu │
│                   │                                  │                 │ www.example.net │
└───────────────────┴──────────────────────────────────┴─────────────────┴─────────────────┘
```

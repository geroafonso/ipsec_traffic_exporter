#!/usr/bin/env python3

###############################################################################
# ipsec_traffic.py
###############################################################################
#  Collects StrongSwan IPsec traffic information using ipsec cli
#  The result is reported in Bytes per IPsec connection
#  Script arguments (not mandatory) to be used:
#  -h, --help            show this help message and exit
#  -a ADDRESS, -address ADDRESS, --address ADDRESS
#                        IPsec Traffic Metrics are exposed on this IP address (default = 0.0.0.0)
#  -p PORT, -port PORT, --port PORT
#                        IPsec Traffic Metrics are exposed on this port (default = 9754)
#  -i INTERVAL, -interval INTERVAL, --interval INTERVAL
#                        IPsec Traffic Metrics read interval in seconds (default = 15)
###############################################################################

import prometheus_client as prom
import os
import time
import argparse as ap

# Exporter default port
exporter_port = 9754
# Default interval in seconds for generating metrics
scrape_interval = 15
# Default IP address is 0.0.0.0
listen_address = '0.0.0.0'

# Get command line arguments
parser = ap.ArgumentParser(description='IPsec Traffic Exporter arguments')
parser.add_argument('-a', '-address', '--address', dest='address', required=False,
                    help='IPsec Traffic Metrics are exposed on this IP address')
parser.add_argument('-p', '-port', '--port', dest='port', required=False, type=int,
                    help='IPsec Traffic Metrics are exposed on this port')
parser.add_argument('-i', '-interval', '--interval', dest='interval', required=False, type=int,
                    help='IPsec Traffic Metrics read interval in seconds')
args = parser.parse_args()

if args.address is not None:
    listen_address = args.address
if args.port is not None:
    exporter_port = args.port
if args.interval is not None:
    scrape_interval = args.interval

def get_ipsec_info(cmd):
    output = os.popen(cmd).read()
    lines = output.split('\n')
    return lines

def parse_ipsec_status(lines):
    connections = {}
    current_connection = None
    connection_state = None

    for line in lines:
        if 'IKEv2' in line and 'dpddelay' in line:
            # Extract connection name
            current_connection = line.split(':')[0].strip()
            connection_state = None
            connections[current_connection] = {"status": 0, "in": 0, "out": 0, "left_subnet": "unknown", "right_subnet": "unknown", "state": "unknown"}
        elif 'ESTABLISHED' in line:
            parts = line.split()
            if current_connection:
                connections[current_connection]["status"] = 1
                connections[current_connection]["state"] = "ESTABLISHED"
        elif 'INSTALLED' in line and current_connection:
            parts = line.split()
            try:
                in_bytes = int(parts[parts.index('bytes_i') - 1].replace(',', ''))
                out_bytes = int(parts[parts.index('bytes_o') - 1].replace(',', ''))
            except (ValueError, IndexError):
                in_bytes = 0
                out_bytes = 0
            connections[current_connection].update({"in": in_bytes, "out": out_bytes})
        elif '===' in line and current_connection:
            parts = line.split('===')
            left_subnet = parts[0].strip().split()[-1]
            right_subnet = parts[1].strip().split()[0]
            connections[current_connection].update({"left_subnet": left_subnet, "right_subnet": right_subnet})

    return connections

def main():
    traffic_gauge = prom.Gauge(
        'ipsec_traffic',
        'Display IPsec Traffic Info',
        ['connection', 'name', 'left_subnet', 'right_subnet', 'direction', 'state']
    )
    status_gauge = prom.Gauge(
        'ipsec_connection_status',
        'Display IPsec Connection Status',
        ['connection', 'name', 'state']
    )
    prom.start_http_server(exporter_port, addr=listen_address)

    while True:
        traffic_list = get_ipsec_info("sudo ipsec statusall")
        connections = parse_ipsec_status(traffic_list)

        traffic_gauge.clear()
        status_gauge.clear()
        for conn, data in connections.items():
            status_gauge.labels(conn, conn, data['state']).set(data['status'])
            traffic_gauge.labels(
                conn,
                conn,
                data.get('left_subnet', 'unknown'),
                data.get('right_subnet', 'unknown'),
                'in',
                data['state']
            ).set(data['in'])
            traffic_gauge.labels(
                conn,
                conn,
                data.get('left_subnet', 'unknown'),
                data.get('right_subnet', 'unknown'),
                'out',
                data['state']
            ).set(data['out'])

        time.sleep(scrape_interval)

if __name__ == '__main__':
    main()


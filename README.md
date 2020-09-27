# IPsec Traffic Exporter for Libreswan

## This is a Prometheus exporter in Python running as OS service

### IPsec Traffic metrics returned by the exporter

The IPsec Traffic is returned in Bytes per the following ipsec parameters: (connection, left_subnet, right_subnet, direction(in/out)).

### Prerequisites for installation

```shell
pip install prometheus_client
```

### Script location

On your server where Libreswan IPsec runs, copy the script in /usr/local/bin/ and make it executable:

```shell
cp ipsec_traffic.py /usr/local/bin/
chown root. /usr/local/bin/ipsec_traffic.py
chmod 755 /usr/local/bin/ipsec_traffic.py
```

### Run with help

```shell
$ /usr/local/bin/ipsec_traffic.py --help
usage: ipsec_traffic.py [-h] [-p PORT] [-i INTERVAL]

IPsec Traffic Exporter arguments

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, -port PORT, --port PORT
                        IPsec Traffic Metrics are exposed on this port
  -i INTERVAL, -interval INTERVAL, --interval INTERVAL
                        IPsec Traffic Metrics read interval in seconds
```

### Run for test purpose

The user that runs the command should have sudo rights because the scripts is calling ipsec command.

```shell
/usr/local/bin/ipsec_traffic.py
```

or run with custom port and interval:

```shell
/usr/local/bin/ipsec_traffic.py -p 48989 -i 32
```

You may check in another terminal if the default port (i.e. 9754) or custom port (e.g. above 48989) is open:

```shell
$ ss -nlt
State      Recv-Q Send-Q    Local Address:Port    Peer Address:Port
LISTEN     0      128                   *:22                 *:*
LISTEN     0      5                     *:9754               *:*
LISTEN     0      128                [::]:22              [::]:*
```

You may also check the metrics returned by the ipsec_traffic_exporter

```shell
curl localhost:9754
```

The result may be similar with:

```raw
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 3.91798784e+08
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 1.5609856e+07
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.60122002164e+09
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 0.16999999999999998
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 7.0
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1024.0
# HELP python_info Python platform information
# TYPE python_info gauge
python_info{implementation="CPython",major="2",minor="7",patchlevel="5",version="2.7.5"} 1.0
# HELP ipsec_traffic Display IPsec Traffic Info
# TYPE ipsec_traffic gauge
ipsec_traffic{connection="dev-01",direction="out",left_subnet="10.153.214.0/24",right_subnet="10.123.71.0/24"} 7.386561e+06
ipsec_traffic{connection="dev-07",direction="out",left_subnet="10.153.214.0/24",right_subnet="10.232.81.0/22"} 26544.0
ipsec_traffic{connection="dev-10",direction="in",left_subnet="10.153.214.0/24",right_subnet="10.10.49.0/22"} 1.87714721e+08
ipsec_traffic{connection="dev-01",direction="in",left_subnet="10.153.214.0/24",right_subnet="10.123.71.0/24"} 5.69280513e+08
ipsec_traffic{connection="dev-07",direction="in",left_subnet="10.153.214.0/24",right_subnet="10.232.81.0/22"} 26544.0
ipsec_traffic{connection="dev-10",direction="out",left_subnet="10.153.214.0/24",right_subnet="10.10.49.0/22"} 1.41831654e+08
```

### The service unit config file

Create file `/etc/systemd/system/ipsec_traffic.service` with the following content:

```shell
[Unit]
Description=IPsec Traffic Exporter
Requires=network.target
After=network.target ipsec.service

[Service]
ExecStart=/usr/local/bin/ipsec_traffic.py

[Install]
WantedBy=multi-user.target
```

### First service start

Service daemon reload:

```shell
systemctl daemon-reload
```

Enable and start the service:

```shell
systemctl enable ipsec_traffic
systemctl start ipsec_traffic
```

Check the service status:

```shell
systemctl status ipsec_traffic
```

The output of service status may be similar with:

```shell
Redirecting to /bin/systemctl status ipsec_traffic.service
● ipsec_traffic.service - IPsec Traffic Exporter
   Loaded: loaded (/etc/systemd/system/ipsec_traffic.service; enabled; vendor preset: disabled)
   Active: active (running) since Fri 2020-09-25 17:14:24 EEST; 8min ago
 Main PID: 6317 (python)
   CGroup: /system.slice/ipsec_traffic.service
           └─6317 python /usr/local/bin/ipsec_traffic.py

Sep 25 17:21:26 my-vpn-node sudo[7251]:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/sbin/ipsec status
Sep 25 17:21:26 my-vpn-node sudo[7255]:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/sbin/ipsec trafficstatus
```

By default the service will expose port **9754** and the metrics will be available either in / or in /metrics

### Change the exporter port

You may change the port by changing the ExecStart in service unit:

```shell
ExecStart=/usr/local/bin/ipsec_traffic.py --port=56789
```

After changing the port you need to restart the service.

### Change the running interval

You may change the running interval (in seconds) by changing the ExecStart in service unit:

```shell
ExecStart=/usr/local/bin/ipsec_traffic.py --interval=10
```

After changing the interval you need to restart the service.

### Allow the exporter port in firewall

In order for the exporter metrics to be accessible to an external Prometheus server
you need to allow the access to the port in the server firewall.
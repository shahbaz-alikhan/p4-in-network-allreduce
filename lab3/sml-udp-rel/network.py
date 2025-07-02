"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from lib import config # do not import anything before this
from p4app import P4Mininet
from mininet.topo import Topo
from mininet.cli import CLI
import os

NUM_WORKERS = 3 # TODO: Make sure your program can handle larger values

# Simple logic to allocate IP and MAC addresses based on the worker ID
def getWorkerIP(wid):
    return "10.0.0.%d" % (wid + 1)

def getWorkerMAC(wid):
    return "00:00:00:00:01:%02x" % (wid + 1)

def getSwitchIP():
    return "10.0.0.100"

def getSwitchMAC():
    return "00:00:00:00:01:00"

class SMLTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Create the switch
        sw = self.addSwitch('s1')

        # Create the workers
        for i in range(NUM_WORKERS):
            worker = self.addHost(
                'w%d' % i, ip=getWorkerIP(i), mac=getWorkerMAC(i))
            self.addLink(worker, sw, port2=i+1)  # Start from port 1

def RunWorkers(net):
    """
    Starts the workers and waits for their completion.
    Redirects output to logs/<worker_name>.log (see lib/worker.py, Log())
    This function assumes worker i is named 'w<i>'. Feel free to modify it
    if your naming scheme is different
    """
    worker = lambda rank: "w%i" % rank
    log_file = lambda rank: os.path.join(os.environ['APP_LOGS'], "%s.log" % worker(rank))

    # Build environment string
    env_vars = []
    for key in ['APP_LOGS', 'APP_TEST', 'APP_ROOT']:
        if key in os.environ:
            env_vars.append(f'{key}={os.environ[key]}')

    env_string = ' '.join(env_vars)

    for i in range(NUM_WORKERS):
        # Run with environment variables set inline
        cmd = f'{env_string} python worker.py {i} > {log_file(i)} 2>&1'
        net.get(worker(i)).sendCmd(cmd)

    for i in range(NUM_WORKERS):
        net.get(worker(i)).waitOutput()

def RunControlPlane(net):
    """
    One-time control plane configuration
    """
    sw = net.get('s1')

    # Create multicast group for broadcasting aggregation results
    # Include all worker ports (1 to NUM_WORKERS)
    worker_ports = list(range(1, NUM_WORKERS + 1))
    sw.addMulticastGroup(mgid=1, ports=worker_ports)
    print(f"Created multicast group 1 with ports: {worker_ports}")

    # Configure hosts for raw socket access
    for i in range(NUM_WORKERS):
        worker = net.get(f'w{i}')

        # Debug: show interface info
        print(f"\nWorker w{i} interfaces:")
        print(worker.cmd('ip link show'))

        # The interface inside the mininet host is just 'eth0', not 'w{i}-eth0'
        # Ensure interface is up
        worker.cmd('ip link set eth0 up')

        # Make sure the worker has the correct IP and MAC addresses
        worker_ip = getWorkerIP(i)
        worker_mac = getWorkerMAC(i)

        # Configure IP address
        worker.cmd('ip addr flush dev eth0')
        worker.cmd(f'ip addr add {worker_ip}/24 dev eth0')

        # Set MAC address explicitly
        worker.cmd(f'ip link set dev eth0 address {worker_mac}')

        # Disable IPv6 to avoid those packets
        worker.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true')
        worker.cmd('sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 2>/dev/null || true')

        # Add route for broadcast
        worker.cmd('ip route add 10.0.0.255/32 dev eth0')

        # Enable broadcast reception
        worker.cmd('echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null || true')

        print(f"Configured worker w{i}: IP={worker_ip}, MAC={worker_mac}")

        # Show final configuration
        print(worker.cmd('ip addr show eth0'))

    print("Control plane configuration completed")

topo = SMLTopo()
net = P4Mininet(program="p4/main.p4", topo=topo)
net.run_control_plane = lambda: RunControlPlane(net)
net.run_workers = lambda: RunWorkers(net)
net.start()
net.run_control_plane()
CLI(net)
net.stop()

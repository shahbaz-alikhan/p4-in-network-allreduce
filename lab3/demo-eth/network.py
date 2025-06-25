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

NUM_WORKERS = 2 # TODO: Make sure your program can handle larger values


# Simple logic to allocate IP and MAC addresses based on the worker ID
def getWorkerIP(wid):
    return "10.0.0.%d" % (wid + 1)

def getWorkerMAC(wid):
    return "00:00:00:00:01:%02x" % (wid + 1)

class SMLTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # TODO: Implement me. Feel free to modify the constructor signature
        # NOTE: Make sure worker names are consistent with RunWorkers() below
        
        # Create the switch
        sw = self.addSwitch('s1')

        # Create the workers
        for i in range(NUM_WORKERS):
            worker = self.addHost(
                'w%d' % i, ip=getWorkerIP(i), mac=getWorkerMAC(i))
            self.addLink(worker, sw, port2=i)

def RunWorkers(net):
    """
    Starts the workers and waits for their completion.
    Redirects output to logs/<worker_name>.log (see lib/worker.py, Log())
    This function assumes worker i is named 'w<i>'. Feel free to modify it
    if your naming scheme is different
    """
    worker = lambda rank: "w%i" % rank
    log_file = lambda rank: os.path.join(os.environ['APP_LOGS'], "%s.log" % worker(rank))
    for i in range(NUM_WORKERS):
        net.get(worker(i)).sendCmd('python worker.py %d > %s' % (i, log_file(i)))
    for i in range(NUM_WORKERS):
        net.get(worker(i)).waitOutput()

def RunControlPlane(net):
    """
    One-time control plane configuration
    """
    # TODO: Implement me (if needed)
    
    sw = net.get('s1')
    # Use function insertTableEntry from p4app/src/p4_mininet.py to insert table entries
    
    # Bidirectional forwarding rules
    sw.insertTableEntry(table_name='TheIngress.ethernet_table',
                        match_fields={'hdr.eth.dstAddr': '00:00:00:00:01:01'},
                        action_name='TheIngress.l2_forward',
                        action_params={'port': 0})
    sw.insertTableEntry(table_name='TheIngress.ethernet_table',
                        match_fields={'hdr.eth.dstAddr': '00:00:00:00:01:02'},
                        action_name='TheIngress.l2_forward',
                        action_params={'port': 1})
    
    # Multicast ARP requests
    sw.insertTableEntry(table_name='TheIngress.ethernet_table',
                        match_fields={'hdr.eth.dstAddr': 'ff:ff:ff:ff:ff:ff'},
                        action_name='TheIngress.multicast',
                        action_params={'mgid': 1})
    
    # Use function addMulticastGroup from p4app/src/p4_mininet.py to add a multicast group
    sw.addMulticastGroup(mgid=1, ports=range(NUM_WORKERS))


topo = SMLTopo() # TODO: Create an SMLTopo instance
net = P4Mininet(program="p4/main.p4", topo=topo)
net.run_control_plane = lambda: RunControlPlane(net)
# net.run_workers = lambda: RunWorkers(net)             # We do not need the worker script in this demo
net.start()
net.run_control_plane()
CLI(net)
net.stop()
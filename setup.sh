#!/bin/bash
# setup.sh - P4 environment setup script for Lab 3

echo "=== Starting Lab 3 Environment Setup ==="

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install essential development tools
sudo apt-get install -y build-essential cmake git vim curl wget \
    automake libtool libgc-dev bison flex libfl-dev libgmp-dev \
    libboost-dev libboost-iostreams-dev libboost-graph-dev llvm \
    pkg-config python3 python3-pip tcpdump

# Install P4 specific dependencies
sudo apt-get install -y libpcap-dev libboost-test-dev \
    libboost-program-options-dev libboost-system-dev \
    libboost-filesystem-dev libboost-thread-dev libevent-dev \
    libssl-dev protobuf-compiler libprotobuf-dev

# Install networking and debugging tools
sudo apt-get install -y mininet net-tools iproute2 bridge-utils \
    wireshark tcpdump iperf3 traceroute htop tree

# Install Python packages for networking
pip3 install --user scapy ipaddr ply grpcio grpcio-tools protobuf psutil numpy

# Set up lab3 directory structure
cd /home/vagrant/lab3
mkdir -p lab3-level1/{p4,src,logs,configs}

# Check if we have the lab repository
if [ ! -d "lab3" ]; then
    echo "Cloning lab repository..."
    git clone --depth 1 https://github.com/upb-cn/ans-ss25.git .
fi

# Install P4 development environment
echo "=== Installing P4 Development Tools ==="

# Clone and build P4C compiler
cd /home/vagrant
if [ ! -d "p4c" ]; then
    git clone --recursive https://github.com/p4lang/p4c.git
    cd p4c
    mkdir build && cd build
    cmake ..
    make -j$(nproc)
    sudo make install
    sudo ldconfig
fi

# Clone and build BMv2 software switch
cd /home/vagrant
if [ ! -d "behavioral-model" ]; then
    git clone https://github.com/p4lang/behavioral-model.git
    cd behavioral-model
    ./autogen.sh
    ./configure --enable-debugger
    make -j$(nproc)
    sudo make install
    sudo ldconfig
fi

# Set up environment variables
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib' >> ~/.bashrc

echo "=== Lab 3 Environment Setup Complete ==="
echo "Use 'vagrant ssh' to connect to the VM"

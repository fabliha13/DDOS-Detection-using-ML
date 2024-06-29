# SDN Network Simulation Using Mininet

## Objective
This is a demonstration of setting up a basic Software-Defined Networking (SDN) topology using Mininet, allowing us to simulate SDN network environments for testing and experimentation.

## Network Setup

- **Topology**: The network consists of two hosts (`h1`, `h2`), one Open vSwitch bridge (`s1`), and a controller.
- **Links**: Host `h1` is linked to switch `s1` via `h1-eth0:s1-eth1`, and host `h2` is linked to switch `s1` via `h2-eth0:s1-eth2`.
- **IP Addresses**:
  - `h1`: `10.0.0.1`
  - `h2`: `10.0.0.2`

## CLI Operations
The following commands were used to configure and interact with the Mininet simulation:

- **`sudo mn`**: Initializes the Mininet environment.
- **`net`**: Displays the network components, including hosts and switches.
- **`dump`**: Shows the current state of the network, including host information and switch connections.
- **`pingall`**: Checks connectivity across all hosts in the network. A 0% packet loss indicates successful network configuration.
- **`xterm h1, h2`**: Opens separate terminal windows for each host for additional testing or command execution.
- **`wireshark`**: Opens Wireshark for detailed packet analysis and traffic monitoring.

## Remarks
The basic topology setup was successful, with both hosts able to communicate through the switch with no packet loss. This confirms a stable network configuration.

## Visualization
To visualize the topology, we used Mininet's built-in visual editor, `miniedit`. This tool allowed us to graphically construct and modify network topologies for easier configuration and experimentation.


## Network Controller
To set up the network controller in a Software-Defined Networking (SDN) environment, there are several robust options available. Popular SDN controllers include ONOS, RYU, POX, OpenDaylight, and others.

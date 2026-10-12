# IPv4 Network Dataplane Router

A low-level, fully functional IPv4 router dataplane implemented in pure C. This project simulates the core routing operations of a network router, directly manipulating Ethernet, IPv4, ARP, and ICMP headers to route packets across a virtual network topology.

## 🚀 Key Features

*   **IPv4 Packet Forwarding:** Implements the Longest Prefix Match (LPM) algorithm to determine the optimal next-hop interface for incoming packets based on a static routing table.
*   **Dynamic ARP Resolution:** 
    *   Dynamically resolves Next-Hop IP addresses to MAC addresses via ARP Requests/Replies.
    *   Maintains and updates a local ARP Cache.
    *   Implements a **packet queueing system** to buffer packets while waiting for pending ARP replies, ensuring zero data loss during MAC discovery.
*   **ICMP Control Messaging:** Fully compliant with standard network diagnostics:
    *   **Echo Reply (Type 0):** Responds to `ping` requests directed at the router's interfaces.
    *   **Destination Unreachable (Type 3):** Drops packets and notifies the sender if no route is found in the routing table.
    *   **Time Exceeded (Type 11):** Drops packets and notifies the sender if the IPv4 Time-To-Live (TTL) expires in transit.
*   **Data Integrity:** Validates and recalculates IPv4 and ICMP checksums according to RFC specifications before forwarding.

## 🧠 Architecture & Forwarding Logic

When a packet arrives at any of the router's interfaces, the dataplane follows a strict processing pipeline:

1.  **L2/L3 Extraction:** The Ethernet and IPv4/ARP headers are extracted and converted from network to host byte order.
2.  **ARP Processing:** 
    *   If it's an ARP Request for the router, it generates an ARP Reply.
    *   If it's an ARP Reply, it updates the ARP table, processes the internal waiting queue, and dispatches all buffered packets destined for that MAC address.
3.  **IPv4 Validation:** Verifies the IPv4 checksum. Corrupt packets are immediately dropped.
4.  **Local Delivery:** If the packet is an ICMP Echo Request targeted at the router's IP, an ICMP Echo Reply is constructed and sent back.
5.  **TTL Check:** Decrements the TTL. If `TTL <= 1`, the packet is dropped, and an ICMP Time Exceeded message is routed back to the source.
6.  **Routing (LPM):** Queries the routing table. If no route matches, an ICMP Destination Unreachable message is returned.
7.  **L2 Encapsulation:** Queries the ARP table for the next-hop MAC.
    *   *Hit:* Updates the Ethernet header (Source MAC = Router Interface, Dest MAC = Next Hop) and transmits.
    *   *Miss:* Enqueues the packet and broadcasts an ARP Request.

## 🛠️ Tech Stack

*   **Language:** C
*   **Concepts:** Network Protocols (L2/L3), Packet Manipulation, Byte Order (Endianness), Queue Data Structures, Checksum Algorithms.

## ⚙️ How to Build and Run

### Prerequisites
*   A Linux environment.
*   `gcc` and `make`.

### Compilation
Navigate to the project root and run `make` to compile the router executable:
```bash
make

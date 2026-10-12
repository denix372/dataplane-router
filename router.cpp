#include <iostream>
#include <vector>
#include <queue>
#include <unordered_map>
#include <algorithm>
#include <cstring>
#include <memory>
#include <arpa/inet.h>

extern "C" {
    #include "protocols.h"
    #include "lib.h"
}

// Constants
constexpr uint16_t kEtherTypeIp = 0x0800;
constexpr uint16_t kEtherTypeArp = 0x0806;
constexpr uint16_t kArpOpRequest = 1;
constexpr uint16_t kArpOpReply = 2;
constexpr uint8_t kIcmpTypeEchoReply = 0;
constexpr uint8_t kIcmpTypeDestUnreachable = 3;
constexpr uint8_t kIcmpTypeEchoRequest = 8;
constexpr uint8_t kIcmpTypeTimeExceeded = 11;

struct QueuedPacket {
    std::vector<uint8_t> buf;
    route_table_entry route;
};

class Router {
public:
    Router(const std::string& rtable_path) {
        // Allocate space for initial rtable read
        std::vector<route_table_entry> raw_rtable(100000);
        int rtable_len = read_rtable(rtable_path.c_str(), raw_rtable.data());
        
        InitializeRouteTable(raw_rtable, rtable_len);
    }

    void Run() {
        std::vector<uint8_t> buf(MAX_PACKET_LEN);
        while (true) {
            size_t len;
            int interface = recv_from_any_link(reinterpret_cast<char*>(buf.data()), &len);
            if (interface < 0) continue;

            auto* eth_hdr = reinterpret_cast<ether_hdr*>(buf.data());

            if (ntohs(eth_hdr->ethr_type) == kEtherTypeArp) {
                HandleArp(buf.data(), len, interface);
            } else if (ntohs(eth_hdr->ethr_type) == kEtherTypeIp) {
                HandleIpv4(buf.data(), len, interface);
            }
        }
    }

private:
    // Routing table grouped by mask length for LPM
    // index 0-32 represents mask length
    std::vector<route_table_entry> route_buckets[33];
    std::unordered_map<uint32_t, std::vector<uint8_t>> arp_cache;
    std::queue<std::unique_ptr<QueuedPacket>> packet_queue;

    void InitializeRouteTable(const std::vector<route_table_entry>& raw_rtable, int len) {
        for (int i = 0; i < len; ++i) {
            int mask_len = __builtin_popcount(ntohl(raw_rtable[i].mask));
            route_buckets[mask_len].push_back(raw_rtable[i]);
        }

        // Sort each bucket by prefix for binary search if needed, 
        // though linear search within a bucket is usually fast enough
        for (auto& bucket : route_buckets) {
            std::sort(bucket.begin(), bucket.end(), [](const route_table_entry& a, const route_table_entry& b) {
                return ntohl(a.prefix) < ntohl(b.prefix);
            });
        }
    }

    route_table_entry* GetBestRoute(uint32_t dest_ip) {
        for (int i = 32; i >= 0; --i) {
            if (route_buckets[i].empty()) continue;

            for (auto& entry : route_buckets[i]) {
                if (entry.prefix == (dest_ip & entry.mask)) {
                    return &entry;
                }
            }
        }
        return nullptr;
    }

    void SendIcmp(uint8_t* orig_buf, size_t orig_len, int interface, uint8_t type) {
        auto* eth_hdr = reinterpret_cast<ether_hdr*>(orig_buf);
        auto* ip_hdr = reinterpret_cast<ip_hdr*>(orig_buf + sizeof(ether_hdr));
        auto* icmp_hdr = reinterpret_cast<icmp_hdr*>(orig_buf + sizeof(ether_hdr) + sizeof(ip_hdr));

        size_t icmp_len;
        if (type == kIcmpTypeDestUnreachable || type == kIcmpTypeTimeExceeded) {
            size_t data_len = sizeof(struct ip_hdr) + 8;
            std::memmove(reinterpret_cast<char*>(icmp_hdr) + sizeof(icmp_hdr), ip_hdr, data_len);
            icmp_len = sizeof(icmp_hdr) + data_len;
        } else {
            icmp_len = orig_len - sizeof(ether_hdr) - sizeof(ip_hdr);
        }

        icmp_hdr->mtype = type;
        icmp_hdr->mcode = 0;
        icmp_hdr->check = 0;
        icmp_hdr->check = htons(checksum(reinterpret_cast<uint16_t*>(icmp_hdr), icmp_len));

        ip_hdr->dest_addr = ip_hdr->source_addr;
        ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
        ip_hdr->tot_len = htons(sizeof(ip_hdr) + icmp_len);
        ip_hdr->proto = 1;
        ip_hdr->ttl = 64;
        ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum(reinterpret_cast<uint16_t*>(ip_hdr), sizeof(ip_hdr)));

        std::memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
        get_interface_mac(interface, eth_hdr->ethr_shost);

        send_to_link(sizeof(ether_hdr) + sizeof(ip_hdr) + icmp_len, reinterpret_cast<char*>(orig_buf), interface);
    }

    void HandleArp(uint8_t* buf, size_t len, int interface) {
        auto* arp_hdr = reinterpret_cast<struct arp_hdr*>(buf + sizeof(ether_hdr));

        if (ntohs(arp_hdr->opcode) == kArpOpRequest) {
            if (arp_hdr->tprotoa != inet_addr(get_interface_ip(interface))) return;

            arp_hdr->opcode = htons(kArpOpReply);
            std::swap(arp_hdr->sprotoa, arp_hdr->tprotoa);
            std::memcpy(arp_hdr->thwa, arp_hdr->shwa, 6);
            get_interface_mac(interface, arp_hdr->shwa);

            auto* eth_hdr = reinterpret_cast<ether_hdr*>(buf);
            std::memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
            get_interface_mac(interface, eth_hdr->ethr_shost);

            send_to_link(len, reinterpret_cast<char*>(buf), interface);

        } else if (ntohs(arp_hdr->opcode) == kArpOpReply) {
            std::vector<uint8_t> mac(6);
            std::memcpy(mac.data(), arp_hdr->shwa, 6);
            arp_cache[arp_hdr->sprotoa] = mac;

            // Process waiting packets
            size_t q_size = packet_queue.size();
            for (size_t i = 0; i < q_size; ++i) {
                auto p = std::move(packet_queue.front());
                packet_queue.pop();

                if (p->route.next_hop == arp_hdr->sprotoa) {
                    auto* eth = reinterpret_cast<ether_hdr*>(p->buf.data());
                    std::memcpy(eth->ethr_dhost, arp_hdr->shwa, 6);
                    get_interface_mac(p->route.interface, eth->ethr_shost);
                    send_to_link(p->buf.size(), reinterpret_cast<char*>(p->buf.data()), p->route.interface);
                } else {
                    packet_queue.push(std::move(p));
                }
            }
        }
    }

    void SendArpRequest(uint32_t next_hop, int interface) {
        std::vector<uint8_t> buf(sizeof(ether_hdr) + sizeof(arp_hdr), 0);
        auto* eth = reinterpret_cast<ether_hdr*>(buf.data());
        auto* arp = reinterpret_cast<arp_hdr*>(buf.data() + sizeof(ether_hdr));

        std::memset(eth->ethr_dhost, 0xFF, 6);
        get_interface_mac(interface, eth->ethr_shost);
        eth->ethr_type = htons(kEtherTypeArp);

        arp->hw_type = htons(1);
        arp->proto_type = htons(kEtherTypeIp);
        arp->hw_len = 6;
        arp->proto_len = 4;
        arp->opcode = htons(kArpOpRequest);
        std::memcpy(arp->shwa, eth->ethr_shost, 6);
        arp->sprotoa = inet_addr(get_interface_ip(interface));
        arp->tprotoa = next_hop;

        send_to_link(buf.size(), reinterpret_cast<char*>(buf.data()), interface);
    }

    void HandleIpv4(uint8_t* buf, size_t len, int interface) {
        auto* ip_hdr = reinterpret_cast<struct ip_hdr*>(buf + sizeof(ether_hdr));

        if (checksum(reinterpret_cast<uint16_t*>(ip_hdr), sizeof(struct ip_hdr)) != 0) return;

        // Check if destined for router
        if (ip_hdr->dest_addr == inet_addr(get_interface_ip(interface))) {
            auto* icmp = reinterpret_cast<icmp_hdr*>(buf + sizeof(ether_hdr) + sizeof(ip_hdr));
            if (icmp->mtype == kIcmpTypeEchoRequest) {
                SendIcmp(buf, len, interface, kIcmpTypeEchoReply);
                return;
            }
        }

        auto* route = GetBestRoute(ip_hdr->dest_addr);
        if (!route) {
            SendIcmp(buf, len, interface, kIcmpTypeDestUnreachable);
            return;
        }

        if (ip_hdr->ttl <= 1) {
            SendIcmp(buf, len, interface, kIcmpTypeTimeExceeded);
            return;
        }

        ip_hdr->ttl--;
        ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum(reinterpret_cast<uint16_t*>(ip_hdr), sizeof(struct ip_hdr)));

        if (arp_cache.count(route->next_hop)) {
            auto* eth = reinterpret_cast<ether_hdr*>(buf);
            std::memcpy(eth->ethr_dhost, arp_cache[route->next_hop].data(), 6);
            get_interface_mac(route->interface, eth->ethr_shost);
            send_to_link(len, reinterpret_cast<char*>(buf), route->interface);
        } else {
            auto p = std::make_unique<QueuedPacket>();
            p->buf.assign(buf, buf + len);
            p->route = *route;
            packet_queue.push(std::move(p));
            SendArpRequest(route->next_hop, route->interface);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) return -1;
    init(argv + 2, argc - 2);
    
    Router router(argv[1]);
    router.Run();

    return 0;
}
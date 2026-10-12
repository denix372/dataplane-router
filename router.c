// Baran Denis-Constantin 322CC
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <arpa/inet.h>

// Ne redefinim noi valorile pentru ethertype ca in laboratorul 4
// valorile sunt explicate aici https://pcom.pages.upb.ro/tema1/ethernet.html
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP		0x0800	/* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP		0x0806	/* ARP protocol */
#endif

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
//struct mac_entry *mac_table;
//int mac_table_len;
// Acum avem Arp Table in loc de mac table

// Folosim o structura de Hashtable unde functia de hash
// este lungimea mastii iar  entrie reprezinta vectorul
// pe care il vom sorta dupa prefix
struct route_table{
	struct route_table_entry *entries;
	int size;
	int capacity;
};

// structura de tip packet pe care o folosim pentru a
// pune packetele in coada cand asteptam un Arp reply
struct packet {
	char *buf;
	size_t len;
	struct route_table_entry *entry;
};

struct arp_table_entry *arp_table;
struct route_table route_table[33];
int arp_table_len = 0;
queue q;

// Functie care numara cati de 1 are masca, deci identifica lungimea mastii
// incepand cu cel mai Seminificativ bit (1U << 31) identifica MSB -ul
int get_mask_len(uint32_t mask) {
	int len;
	uint32_t host_mask = ntohl(mask);
	for (len = 0; host_mask & (1U << 31); len++)
		host_mask <<= 1;
	return len;
}

// comparator pentru qsort si bsearch, sortare dupa prefix
int compare_prefixes(const void *a, const void *b) {
	struct route_table_entry *e1 = (struct route_table_entry *)a;
	struct route_table_entry *e2 = (struct route_table_entry *)b;

	return ntohl(e1->prefix) - ntohl(e2->prefix);
}

// Initializam intrarile in tabela de rutare, avem 33 de posibilitati de masti
// si pentru fiecare lungime de masca, alocam prefixele in vectorul entries
// Vectorii de prefixe se aloca dinamic si le dublam capacitatea cand se umple
void init_route_table(struct route_table_entry *rtable, int rtable_len) {
	for (int i = 0; i < rtable_len; i++) {
		int len = get_mask_len(rtable[i].mask);

		if (route_table[len].size == route_table[len].capacity) {
			if (route_table[len].capacity == 0)
				route_table[len].capacity = 1;
			else
				route_table[len].capacity *= 2;

			route_table[len].entries = realloc(route_table[len].entries,
				route_table[len].capacity * sizeof(struct route_table_entry));
		}
		route_table[len].entries[route_table[len].size++] = rtable[i];
	}

	// sortam fiecare vector de prefixe pentru a folosi bsearch
	// astfel incat sa obtinem un timp in log n mai bun decat cel liniar
	for (int i = 0; i <= 32; i++)
		if (route_table[i].size > 1)
			qsort(route_table[i].entries, route_table[i].size,
				sizeof(struct route_table_entry), compare_prefixes);
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */

	/*for (int i = 0; i < rtable_len; i++)
		// Cum tabela este sortată, primul match este prefixul ce mai specific
		if (rtable[i].prefix == (ip_dest & rtable[i].mask))
			return &rtable[i];
	return NULL; */

	/* Algoritmul de lPM cautam cea mai specifica masca (incepem de la masca
	care are cei mai multi biti de 1 adica 32) si facem bsearch pe vectorul
	de prefixe care stim ca este sortat. Worst case, complexitatea e rea cand
	trebuie sa cautam fiecare masca deci avem O(32 * log m) unde m este
	vectorul de prefixe. Daca se intampla ca toate intrarile sa aiba o singura
	masca atunci complexitatea devine O(32 * log n) care e mai buna
	decat cautarea liniara O(n)*/
	for (int i = 32; i >= 0; i--) {

		if (route_table[i].size == 0)
			continue;

		// Elementul cautat este ip-ul destinatie & masca adica adresa de retea
		// Folosind bsearch sa obtinem cautare in O(log n)
		struct route_table_entry key;
		key.prefix = ip_dest & route_table[i].entries[0].mask;

		struct route_table_entry *best = bsearch(&key, route_table[i].entries,
			route_table[i].size, sizeof(struct route_table_entry),
			compare_prefixes);
		if (best)
			return best;
	}
	return NULL;
}

// Pastram functia de cautare a ip ului in arp ul global ca in laboratorul 4
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the MAC table and search for an entry
	 * that matches given_ip. */

	/* We can iterate thrpigh the mac_table for (int i = 0; i <
	 * mac_table_len; i++) */
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == given_ip)
			return &arp_table[i];

	return NULL;
}

/* Functie generala de trimitere a unui pachet ICMP care pot fi:
- pachete icmp de tip eroare (TTL Expired sau Dest Unreachable)
- pachete icmp de tip ehco reply
Diferenta dintre ele este ca pentru pachetele de tip eroare se pastreaza
"primii 64 de biți din payload-ul pachetului original" asa cum scrie in
pagina temei https://pcom.pages.upb.ro/tema1/icmp.html iar pentru cele de reply
se pastreaza exact acelasi continut*/
void send_icmp(char *buf, size_t len, size_t interface, uint8_t type) {
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(
					buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	size_t icmp_len;
	memset(icmp_hdr, 0, sizeof(struct icmp_hdr));

	if (type == 3 || type == 11) {
		size_t icmp_data_len = sizeof(struct ip_hdr) + 8;
		memmove((char *)icmp_hdr + sizeof(struct icmp_hdr), ip_hdr, icmp_data_len);

		icmp_len = sizeof(struct icmp_hdr) + icmp_data_len;
		len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len;

	} else if (type == 0) {
		icmp_len = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr);
	}

	// pentru ambele recalculam checksum ul headerului ip, interschimbam
	//ip urile si adresele MAC
	icmp_hdr->mtype = type;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_len));

	ip_hdr->dest_addr = ip_hdr->source_addr;
	ip_hdr->source_addr = inet_addr(get_interface_ip(interface));

	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + icmp_len);
	ip_hdr->proto = 1; // numarul decimal pentru ICMP conform https://www.rfc-editor.org/rfc/rfc990
	ip_hdr->ttl = 64;
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

	eth_hdr->ethr_type = htons(ETHERTYPE_IP);
	memmove(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);

	send_to_link(len, buf, interface);
}

/* Functie pentru a calculam nr de elemente dintr-o coada
Folosim 2 cozi pentru a putea determina lungimea si temporar mutam elementele
intr-o alta coada astfel incat sa nu pierdem elementele propriu-zise*/
int queue_size(queue q) {
	int k = 0;
	queue aux = create_queue();

	while(!queue_empty(q))
		queue_enq(aux, queue_deq(q));

	while(!queue_empty(aux)) {
		queue_enq(q, queue_deq(aux));
		k++;
	}

	free(aux);
	return k;
}

/* Functie pentru a raspunde la cererile de tip ARP request
Daca primim un arp request, mai intai verificam daca ip ul destinatie este
adresat direct noua, adica daca adresa noastra ip corespunde adresei ip target.
In caz afirmativ, vom trimite un arp reply construit pe baza acelasi
pachet pentru care interschimbam ip urile si adresele mac, actualizam mac ul
sursa cu cel al interfetei noaste si schimbam si opcode ul in reply (2)
conform standardului iana https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
*/
void handle_arp_requests(char *buf, size_t len, int interface) {
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	if (arp_hdr->tprotoa != inet_addr(get_interface_ip(interface)))
		return;

	uint32_t aux = arp_hdr->tprotoa;
	arp_hdr->tprotoa = arp_hdr->sprotoa;
	arp_hdr->sprotoa = aux;

	memmove(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	memmove(arp_hdr->thwa, eth_hdr->ethr_shost, 6);

	get_interface_mac(interface, eth_hdr->ethr_shost);
	memmove(arp_hdr->shwa, eth_hdr->ethr_shost, 6);

	arp_hdr->opcode = htons(2); // reply
	send_to_link(len, buf, interface);
}

/* Functie pentru a gestiona un reply
Daca primim un reply atunci inseamna ca avem o intrare in arp si stim unde
sa trimitem pachetele din coada. Drept urmare, o salvam asocierae dintre
mac si ip in tabela noastra arp si scoatem pachetele din coada q care asteptau
mac ul respectiv si le trimitem folosim send_link
*/
void handle_arp_reply(char *buf, size_t len, int interface) {
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	arp_table[arp_table_len].ip = arp_hdr->sprotoa;
	memmove(arp_table[arp_table_len++].mac, arp_hdr->shwa, 6);

	int q_len = queue_size(q);

	for (int i = 0; i < q_len; i++) {
		struct packet *p = queue_deq(q);

		// daca pachetul nu este cel asteptat, il bagam inapoi in coada
		if (p->entry->next_hop != arp_hdr->sprotoa) {
			queue_enq(q, p);
			continue;
		}

		memmove(p->buf, arp_hdr->shwa, 6);
		struct ether_hdr *eth_hdr = (struct ether_hdr *)p->buf;
		get_interface_mac(p->entry->interface, eth_hdr->ethr_shost);
		send_to_link(p->len, p->buf, p->entry->interface);

		free(p->buf);
		free(p);
	}
}

/*Trimitem un Arp Request de tip boardcast (a caror destinatie nu o stim)
ca sa aflam Mac-ul unui IP. Folosim adresa de broadcast FF:FF:FF:FF:FF:FF
pentru a face match cu toate host urile. Cerearea va fi gestionata de functia
handle_arp_request si v-om primi inapoi mac ul ca sa putem trimite pachetele
in asteptare*/
void send_arp_request(int next_hop, int interface) {
	char *arp_buf = calloc(MAX_PACKET_LEN, sizeof(char));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)arp_buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(arp_buf + sizeof(struct ether_hdr));
	memset(arp_hdr, 0, sizeof(struct arp_hdr));

	eth_hdr->ethr_type = htons(ETHERTYPE_ARP);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	for (int i = 0; i < 6; i++)
		eth_hdr->ethr_dhost[i] = 0xFF;

	// informatii preluate din exemplul de pachet de tip ARP
	// de pe pagina https://pcom.pages.upb.ro/tema1/arp.html
	arp_hdr->hw_type = htons(1);
	arp_hdr->proto_type = htons(ETHERTYPE_IP);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1);

	memmove(arp_hdr->shwa, eth_hdr->ethr_shost, 6);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	arp_hdr->tprotoa = next_hop;

	send_to_link(sizeof(struct ether_hdr)
			+ sizeof(struct arp_hdr), arp_buf, interface);
	free(arp_buf);
}

int main(int argc, char *argv[])
{
	char *buf = calloc(MAX_PACKET_LEN, sizeof(char)); // buf = packet in lab4

	// Do not modify this line
	init(argv + 2, argc - 2);

	// setam nr maxim de intrari fiind 100.000 ca in enunt https://pcom.pages.upb.ro/tema1/routing_table.html
	/* Code to allocate the MAC and route tables */
	rtable = calloc(100000, sizeof(struct route_table_entry));
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = calloc(100, sizeof(struct arp_table_entry));
	DIE(arp_table == NULL, "memory");

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);

	/* Citim rutele si initializam structura de Hashtable
	Putem apoi sa dam free la memoria alocata pentru ca acum sunt retinute
	in noua structura */
	init_route_table(rtable, rtable_len);
	free(rtable);

	// Initial am testat folosind tabela statica, dar acum schimbat apoi
	// la cea dinamica
	//arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	q = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		// The new signature is this
		// size_t recv_from_any_link(char *frame_data, size_t *length);
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

	// TODO: Implement the router forwarding logic

	/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/* Extract the Ethernet header from the packet. Since protocols are
		 * stacked, the first header is the ethernet header, the next header is
		 * at m.payload + sizeof(struct ether_header) */
		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
		struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

		// in cazul in care avem pachete arp,
		// - daca primim request raspundem cu reply
		// - daca primim reply salvam adresa mac si trimitem pachetele din q
		if (eth_hdr->ethr_type == ntohs(ETHERTYPE_ARP)) {
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			if (ntohs(arp_hdr->opcode) == 1) { // ARP Request
				handle_arp_requests(buf, len, interface);
				continue;
			} else if (ntohs(arp_hdr->opcode)  == 2) { // ARP Reply
				handle_arp_reply(buf, len, interface);
				continue;
			}
		}

		// daca primi alt pachet decat ipv4 il ignoram (drop) ca in laborator
		/* Check if we got an IPv4 packet */
		if (eth_hdr->ethr_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		/* TODO 2.1: Check the ip_hdr integrity using ip_checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) */
		int ok = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
		if (ok) {
			perror("Bad Checksum! Drop packet!");
			continue;
		}

		/* Daca primim un echo request (type 8) adica daca pachetul este pentru
		router, raspundem cu un echo reply (type 0) asa cum scrie si in enunt
		https://pcom.pages.upb.ro/tema1/icmp.html
		*/
		uint32_t interface_ip = inet_addr(get_interface_ip(interface));
		if (ip_hdr->dest_addr == interface_ip) {
			struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(
					buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

			if (icmp_hdr->mtype == 8) {
				send_icmp(buf, len, interface, 0);
				continue;
			}
		}

		/* TODO 2.2: Call get_best_route to find the most specific route, continue; (drop) if null */
		struct route_table_entry *best_router = get_best_route(ip_hdr->dest_addr);
		if (!best_router) {
			printf("No route. Sending Destination Unreachable icmp\n");
			// Daca nu gasim o ruta prin LPM trimitem un ICMP type 3
			send_icmp(buf, len, interface, 3);
			continue;
		}

		/* TODO 2.3: Check TTL > 1. Update TLL. Update checksum  */
		if (ip_hdr->ttl <= 1) {
			printf("TTL expired. Sending TTL Expired icmp");
			// Daca ttl ul ajunge la 0, atunci trimitem un ICMP type 11
			send_icmp(buf, len, interface, 11);
			continue;
		}
		// Actualizam si recalculam checksum ul ca in laborator
		ip_hdr->ttl--;
		ip_hdr->checksum = 0;
		ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

		/* TODO 2.4: Update the ethernet addresses. Use get_mac_entry to find the destination MAC
		 * address. Use get_interface_mac(m.interface, uint8_t *mac) to
		 * find the mac address of our interface. */

		// cautam adresa mac a urmatorului hop in tabela noastra arp
		// daca nu gasim o adresa mac asociata ip ului, trimitem un ARP request
		// cu destinatie de Broadcast. Momentan vom pune pachetul in coada si
		// asteptam pana cand primi arp reply
		struct arp_table_entry *entry = get_arp_entry(best_router->next_hop);
		if (!entry) {
			struct packet *p = calloc(1, sizeof(struct packet));
			p->buf = calloc(len, sizeof(char));
			memmove(p->buf, buf, len);
			p->len = len;
			p->entry = best_router;
			queue_enq(q, p);

			send_arp_request(best_router->next_hop, best_router->interface);
			continue;
		}

		// Call send_to_link(best_router->interface, packet, packet_len);
		memmove(eth_hdr->ethr_dhost, entry->mac, 6);
		get_interface_mac(best_router->interface, eth_hdr->ethr_shost);

		// Fata de laborator, functia are antetul acesta gasi in lib.h
		// int send_to_link(size_t length, char *frame_data, size_t intidx)
		send_to_link(len, buf, best_router->interface);
	}
	free(buf);
}

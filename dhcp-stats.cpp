/*
 * Brno University of Technology
 * Project: ISA DHCP
 * Author: Vladislav Khrisanov (xkhris00)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h> 
#include <set>

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#ifdef __linux__
#include <netinet/ether.h> 
#endif

#include <ncurses.h>
#include <syslog.h>

pcap_t *handle = NULL;
std::set<uint32_t> addresses;

enum mode {file, interface};
enum mode program_mode;

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

typedef struct ListElement {
    uint32_t network_addr;
    uint32_t host_bits;
    uint32_t host_max;
    uint32_t host_cnt;
    int logged;

    struct ListElement *nextElement;
} *ListElementPtr;

typedef struct {
    ListElementPtr firstElement;
    ListElementPtr activeElement;
} List;

// global list of networks:
List network_list;
List *networks = &network_list;

void list_init(List *list) {
    list->firstElement = NULL;
    list->activeElement = NULL;
}

void list_dispose(List *list) {
    ListElementPtr tmpElement;
    //while the list is not empty
    while (list->firstElement != NULL) {
        //delete the first element
        tmpElement = list->firstElement->nextElement;
        free(list->firstElement);
        list->firstElement = tmpElement;
    }
    list->activeElement = NULL;
}

void finish_program(int code) {
    if(program_mode == interface){ 
        endwin();
    }
    if(handle != NULL) {
        pcap_close(handle);
    }
    list_dispose(networks);
    exit(code);
}

void sigint_handler(int signum) {
    finish_program(EXIT_FAILURE);
}

void list_insert_first(List *list, uint32_t network_addr, uint32_t host_bits, uint32_t host_max, uint32_t host_cnt) {
    ListElementPtr newElement = (ListElementPtr) malloc(sizeof(struct ListElement));
    if (newElement == NULL) {
        fprintf(stderr, "Error message: Couldn't allocate memory.\n");
        finish_program(EXIT_FAILURE);
    }
    else {
        //insert the new element
        newElement->network_addr = network_addr;
        newElement->host_bits    = host_bits;
        newElement->host_max     = host_max;
        newElement->host_cnt     = host_cnt;
        newElement->logged = 0;

        newElement->nextElement = list->firstElement;
        list->firstElement = newElement;
    }
}

void list_insert_after(List *list, uint32_t network_addr, uint32_t host_bits, uint32_t host_max, uint32_t host_cnt) {
    //if the list is active
    if (list->activeElement != NULL) {
        ListElementPtr newElement = (ListElementPtr) malloc(sizeof(struct ListElement));
        if (newElement == NULL) {
            fprintf(stderr, "Error message: Couldn't allocate memory.\n");
            finish_program(EXIT_FAILURE);
        }
        else {
            //insert the new element after the active one
            newElement->network_addr = network_addr;
            newElement->host_bits    = host_bits;
            newElement->host_max     = host_max;
            newElement->host_cnt     = host_cnt;
            newElement->logged = 0;

            newElement->nextElement = list->activeElement->nextElement;
            list->activeElement->nextElement = newElement;
        }
    }
}

void list_first(List *list) {
    list->activeElement = list->firstElement;
}

void list_next(List *list) {
    //if the list is active
    if (list->activeElement != NULL) {
        list->activeElement = list->activeElement->nextElement;
    }
}

int list_is_active(List *list) {
    return (list->activeElement != NULL);
}

void compare_net_addresses(List *list, uint32_t yiaddr) {
    // if yiaddr equals to the network address then skip:
    if(list->activeElement->network_addr == yiaddr) {
        return;
    }

    // if yiaddr equals to the broadcast address then skip:
    if((list->activeElement->network_addr + (1 << list->activeElement->host_bits) - 1) == yiaddr) {
        return;
    }

    int host_bits = list->activeElement->host_bits;
    uint32_t yiaddr_net = (yiaddr >> host_bits) << host_bits;

    if(list->activeElement->network_addr == yiaddr_net) {
        list->activeElement->host_cnt++;
        addresses.insert(yiaddr);
    }
}

void print_interface_stats(List *list) {    
    uint32_t host_cnt = list->activeElement->host_cnt;
    uint32_t host_max = list->activeElement->host_max;
    uint32_t host_bits = list->activeElement->host_bits;
    uint32_t prefix_len = 32 - host_bits;
    float percentage = (float)host_cnt / host_max * 100.0;

    struct in_addr addr = {list->activeElement->network_addr};
    addr.s_addr = htonl(addr.s_addr);

    printw("%s/%u %u %u %.2f%%\n", inet_ntoa(addr), prefix_len, host_max, host_cnt, percentage);

    if(percentage >= 50 && list->activeElement->logged == 0) {
        openlog("dhcp-stats", LOG_PID, LOG_USER);
        syslog(LOG_NOTICE, "prefix %s/%u exceeded 50%% of allocations\n", inet_ntoa(addr), prefix_len);
        closelog();
        list->activeElement->logged = 1;
    }
}

void print_file_stats(List *list) {
    uint32_t host_cnt;
    uint32_t host_max;
    uint32_t host_bits;
    uint32_t prefix_len;
    float percentage;
    
    printf("IP-Prefix Max-hosts Allocated addresses Utilization\n");

    list_first(networks);

    while(list_is_active(networks)){
        host_cnt = list->activeElement->host_cnt;
        host_max = list->activeElement->host_max;
        host_bits = list->activeElement->host_bits;
        prefix_len = 32 - host_bits;
        percentage = (float)host_cnt / host_max * 100.0;

        struct in_addr addr = {list->activeElement->network_addr};
        addr.s_addr = htonl(addr.s_addr);

        printf("%s/%u %u %u %.2f%%\n", inet_ntoa(addr), prefix_len, host_max, host_cnt, percentage);

        if(percentage >= 50) {
            openlog("dhcp-stats", LOG_PID, LOG_USER);
            syslog(LOG_NOTICE, "prefix %s/%u exceeded 50%% of allocations\n", inet_ntoa(addr), prefix_len);
            closelog();
        }

        list_next(networks);
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packetptr) {
    struct ether_header *ethhdr;
    struct ip* iphdr;
    struct udphdr *udphdr; 

    ethhdr = (struct ether_header*)packetptr;

    // go past ethernet:

    // standart ethernet:
    if(ntohs(ethhdr->ether_type) == 0x0800) {
        packetptr += 14;
    }
    // 1 vlan tag:
    else if(ntohs(ethhdr->ether_type) == 0x8100) {
        packetptr += 18;
    }
    // 2 vlan tags:
    else if(ntohs(ethhdr->ether_type) == 0x88A8) {
        packetptr += 22;
    }

    iphdr = (struct ip*)packetptr;

    // skip if not IPv4:
    if(iphdr->ip_v != 4) {
        return;
    }

    // skip if not UDP:
    if(iphdr->ip_p != IPPROTO_UDP) {
        return;
    }

    // go past ip:
    packetptr += 4*iphdr->ip_hl;

    // filter packets by source port:
    udphdr = (struct udphdr*)packetptr;
    if(ntohs(udphdr->source) != 67) {
        return;
    }

    // go past udp(fixed 8-bytes header):
    packetptr += 8;

    // get yiaddr in network byte order:
    packetptr += 16;
    uint32_t yiaddr = htonl(*((uint32_t*)packetptr));
    
    // skip if yiaddr is 0.0.0.0:
    if(yiaddr == 0) {
        return;
    }

    // skip if yiaddr has already been processed: 
    if(addresses.count(yiaddr)) {
        return;
    }

    // go to DHCP options:
    packetptr += 224;

    // check if DHCPACK(option 53, option value 5):
    while(1) {
        if(*packetptr == 53){
            if(*(packetptr + 2) == 5) { break; }
            else { return; }
        }
        else if(*packetptr == 255) {
            return;
        }
        else {
            // get to the option length:
            packetptr++;
            // go to the next option:
            packetptr += (*packetptr + 1);
        }
    }

    if(program_mode == interface) {
        clear();
        printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");
    }

    // compare yiaddr network address with all given network addresses:
    list_first(networks);

    while(list_is_active(networks)){
        compare_net_addresses(networks, yiaddr);

        if(program_mode == interface) {
            print_interface_stats(networks);
        }

        list_next(networks);
    }

    if(program_mode == interface) {
        refresh();
    }
}

void invalid_address_error(const char *message, int position) {
    fprintf(stderr, "Error on argument position: (%d)\n", position);
    fprintf(stderr, "Error message: %s.\n", message);
    fprintf(stderr, "For help run: ./dhcp-stats --help\n");
}

void print_help() {
    printf(
    "\n"
    "# DESCRIPTION #\n"
    "\n"
    "   Get utilization statistics on DHCP server for specified pools of addresses.\n"
    "\n"
    "# USAGE #\n"
    "\n"
    "   ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [<ip-prefix> [ ... ]]\n"
    "\n"
    "   e.g.: ./dhcp-stats -i eth0 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22\n"
    "\n"
    "   <ip-prefix> is formatted as network_address/prefix_length.\n"
    "   prefix_length is between 1 and 30.\n"
    "   Any correctly formatted IPv4 network address(host portion is 0) will be accepted.\n"
    "   User is responsible for the semantic validity of the given address.\n"
    "\n"
    "# EXIT #\n"
    "\n"
    "   Use CTRL + C to gracefully exit.\n"
    "\n");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);

    if(argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_help();
        exit(EXIT_SUCCESS);
    }

    if(argc >= 4 && ((strcmp(argv[1], "-r") == 0) || (strcmp(argv[1], "-i") == 0))) {
        if(strcmp(argv[1], "-r") == 0) {
            program_mode = file;
        }
        else {
            program_mode = interface;
        }   
    }
    else {
        fprintf(stderr, "Invalid input, usage:\n"
        "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [<ip-prefix> [ ... ]]\n"
        "./dhcp-stats --help\n");
        exit(EXIT_FAILURE);
    }

    // initialize linked list and start ncurses if needed:
    list_init(networks);

    if(program_mode == interface){ 
        initscr();
    }

    // configure the packet source:
    char errbuf[PCAP_ERRBUF_SIZE];

    if(program_mode == file) { 
        handle = pcap_open_offline(argv[2], errbuf);
    }
    else {
        handle = pcap_open_live(argv[2], BUFSIZ, 0, 100, errbuf);
    }

    if (handle == NULL) {
        fprintf(stderr, "Error message: Can't open the specified device.\n");
        finish_program(EXIT_FAILURE);
    }

    // parse given network addresses and store the information about each one in a linked list:
    int network_count = argc - 3;
    int position = 3;

    while(network_count != 0) {
        char *addr_token = strtok(argv[position], "/");
        struct in_addr received_addr;
        
        if (inet_pton(AF_INET, addr_token, &(received_addr.s_addr)) == 0) {
            invalid_address_error("Invalid network address", position);
            finish_program(EXIT_FAILURE);
        }

        int prefix_len;

        addr_token = strtok(NULL, "/");

        if (addr_token != NULL) {
            prefix_len = atoi(addr_token);
        }
        else {
            invalid_address_error("No prefix length is given", position);
            finish_program(EXIT_FAILURE);
        }

        if(prefix_len < 1 || prefix_len > 30) {
            invalid_address_error("Prefix length is out of range", position);
            finish_program(EXIT_FAILURE);
        }

        int host_bits = 32 - prefix_len;

        // convert the address to network byte order:
        received_addr.s_addr = htonl(received_addr.s_addr);

        // check if it is a network address:
        if(received_addr.s_addr != ((received_addr.s_addr >> host_bits) << host_bits)) {
            invalid_address_error("Invalid network address, host portion should be 0", position);
            finish_program(EXIT_FAILURE);
        }

        int host_max = (1 << host_bits) - 2;

        // save the information in the linked list in the given order:
        if(position == 3) {
            list_insert_first(networks, received_addr.s_addr, host_bits, host_max, 0);
            list_first(networks);
        }
        else {
            list_insert_after(networks, received_addr.s_addr, host_bits, host_max, 0);
            list_next(networks);
        }

        network_count--;
        position++;
    }
    
    // sniff packets:
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error message: %s\n", pcap_geterr(handle));
        finish_program(EXIT_FAILURE);
    }

    // print out gathered statistics for a file:
    if(program_mode == file){ 
        print_file_stats(networks);
    }

    // wait for user input and then close ncurses if needed:
    if(program_mode == interface){ 
        getch();
        endwin();
    }

    finish_program(EXIT_SUCCESS);
}
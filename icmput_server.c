#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#define SNAP_LEN 65535
#define TIMEOUT_MS 1000
#define MIN_STREAM_CAPACITY 10

int verbose = 1;

typedef struct {
    FILE *ptr;
    uint16_t seq_num;
    uint16_t identifier;
    uint8_t open;
} filestream;


filestream *streams = NULL;
size_t streams_open = 0;
size_t streams_capacity = 0;
pcap_t *handle = NULL;

void graceful_shutdown(int signum) {
    printf("Shutting down\n");
    pcap_breakloop(handle);

    for (size_t i = 0; i < streams_open; i++) {
        if (streams[i].open) {
            fclose(streams[i].ptr);
            streams[i].ptr = NULL;
            streams[i].open = 0;
        }
    }
}

filestream *get_stream(uint16_t identifier) {
    for (size_t i = 0; i < streams_open; i++) {
        if (streams[i].identifier == identifier) {
            return &streams[i];
        }
    }
    // need to open new stream
    if (streams_capacity <= streams_open) {
        size_t new_cap = streams_capacity < MIN_STREAM_CAPACITY ? 10 : streams_capacity * 2;
        filestream *new_streams = malloc(sizeof(filestream) * new_cap);
        if (new_streams == NULL) {
            fprintf(stderr, "Could not allocate memory for file streams\n");
            return NULL;
        }
        memset(new_streams, 0, sizeof(filestream) * new_cap);
        memcpy(new_streams, streams, sizeof(filestream) * streams_open);
        free(streams);
        streams = new_streams;
    }
    filestream *result = &streams[streams_open++];
    result->identifier = identifier;
    return result;
}

// helper function to dump packet contents to console
void print_packet(struct icmp6_hdr *icmp_msg, uint16_t packet_size) {
    unsigned char *replydata = (unsigned char *)icmp_msg;
    for (size_t i = 0; i < packet_size; i++) {
        if (i > 0) {
            printf(i % 16 == 0 ? "\n" : " ");
        }
        printf("%02x", replydata[i]);
    }
    printf("\n");
}

void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip6_hdr *ip6_hdr;
    struct icmp6_hdr *icmp6_hdr;
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];

    // Extract IPv6 header
    const size_t LINK_LAYER_HEADER_LEN = 14; // ethernet
    int offset = sizeof(struct ip6_hdr) + LINK_LAYER_HEADER_LEN;
    ip6_hdr = (struct ip6_hdr *)(packet + LINK_LAYER_HEADER_LEN);

    // skip ipv6 extension headers
    while (offset < pkthdr->len) {
        struct ip6_ext *ip6_ext = (struct ip6_ext *)(packet + offset);
        // If we encounter a non-extension header or a fragment header, break
        if (ip6_ext->ip6e_nxt != IPPROTO_ROUTING && ip6_ext->ip6e_nxt != IPPROTO_FRAGMENT && ip6_ext->ip6e_nxt != IPPROTO_HOPOPTS && ip6_ext->ip6e_nxt != IPPROTO_ESP && ip6_ext->ip6e_nxt != IPPROTO_AH) {
            break;
        }
        // Move to the next header
        offset += (ip6_ext->ip6e_len + 1) * 8;
    }

    // Extract ICMPv6 header
    icmp6_hdr = (struct icmp6_hdr *)(packet + offset);
    if (icmp6_hdr->icmp6_type != ICMP6_ECHO_REQUEST) {
        return;
    }

    // Convert source and destination IPv6 addresses to strings
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
    size_t icmp6_data_len = pkthdr->len - LINK_LAYER_HEADER_LEN - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);

    if (verbose) {
        printf("ICMPv6 packet received:\n");
        printf("Source IP: %s\n", src_ip_str);
        printf("Destination IP: %s\n", dst_ip_str);
        printf("Data size: %" PRIu64 " bytes\n", icmp6_data_len);
        printf("ICMPv6 Type: %d\n", icmp6_hdr->icmp6_type);
        printf("ICMPv6 Code: %d\n", icmp6_hdr->icmp6_code);
        printf("ICMP6 Identifier:%" PRIu16 "\n", icmp6_hdr->icmp6_id);
        printf("\n");
        print_packet(icmp6_hdr, icmp6_data_len + sizeof(struct icmp6_hdr));
    }
    filestream *stream = get_stream(icmp6_hdr->icmp6_id);
    char filename[32];
    snprintf(filename, sizeof(filename), "%" PRIu16 ".icmput", stream->identifier);
    if (!stream->open) {
        stream->ptr = fopen(filename, "ab");
        if (stream->ptr == NULL) {
            perror("Could not open file\n");
            abort();
        }
        stream->open = 1;
        printf("Opened new file: %s\n", filename);
    }
    icmp6_data_len = icmp6_data_len > 4096 ? 4096 : icmp6_data_len;
    void *data = (void *)((unsigned char*)icmp6_hdr + sizeof(struct icmp6_hdr));
    // void *data = (void *)packet;
    if (icmp6_data_len != fwrite(data, 1, icmp6_data_len, stream->ptr)) {
        fprintf(stderr, "Failed to write all data for identifier %" PRIu16 "\n", stream->identifier);
    }
    if (verbose) {
        printf("Wrote %" PRIu64 " bytes of data to %s\n", icmp6_data_len, filename);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = graceful_shutdown;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGKILL, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    // Open network interface for capturing
    handle = pcap_open_live("enp0s25", SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // Set filter to capture only ICMP packets
    struct bpf_program fp;
    char filter_exp[] = "icmp6";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, process_packet, NULL);

    // Cleanup
    pcap_close(handle);

    return 0;
}

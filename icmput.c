/*
 * Copyright (c) 2024, Gordin508
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of the software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions.
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * In addition, the following restrictions apply:
 * 
 * 1. The Software and any modifications made to it may not be used for the purpose of training or improving machine learning algorithms,
 * including but not limited to artificial intelligence, natural language processing, or data mining. This condition applies to any derivatives,
 * modifications, or updates based on the Software code. Any usage of the Software in an AI-training dataset is considered a breach of this License.
 * 
 * 2. The Software may not be included in any dataset used for training or improving machine learning algorithms,
 * including but not limited to artificial intelligence, natural language processing, or data mining.
 * 
 * 3. Any person or organization found to be in violation of these restrictions will be subject to legal action and may be held liable
 * for any damages resulting from such use.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>

// default packet size, e.g. used by /bin/ping
#define DEFAULT_PACKET_SIZE 64

// ICMP6 type identifiers (now defined in icmp6.h by default)
// https://www.rfc-editor.org/rfc/rfc4443#section-4.1
// #define ICMP6_ECHO_REQUEST 128
// #define ICMP6_ECHO_REPLY 129


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

struct cli_options {
    char *filepath;
    char *destination;
    int mode;
    size_t packet_size;
};

void print_options(struct cli_options *this) {
    printf("File to send: %s\n", this->filepath);
    printf("Destination: %s\n", this->destination);
    printf("Mode: %d\n", this->mode);
}

// read a file completely into memory (avoid keeping the file handle active for longer than necessary)
unsigned char* read_file(const char* file_path, size_t* file_size) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error opening file: %s\n", file_path);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* content = (unsigned char*)malloc(*file_size); // Allocate memory for file contents
    if (content == NULL) {
        fclose(file);
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    size_t bytes_read = fread(content, 1, *file_size, file);
    fclose(file);

    if (bytes_read != *file_size) {
        free(content);
        fprintf(stderr, "Error reading file: %s\n", file_path);
        return NULL;
    }

    return content;
}

// parse CLI arguments
int parse_args(int argc, char *argv[], struct cli_options *options) {
    int opt;
    memset(options, 0, sizeof(struct cli_options));
    options->packet_size = DEFAULT_PACKET_SIZE;

    // Parse command-line arguments using getopt
    while ((opt = getopt(argc, argv, "f:d:m:")) != -1) {
        switch (opt) {
            case 'f':
                options->filepath = optarg;
                break;
            case 'd':
                options->destination = optarg;
                break;
            case 'm':
                options->mode = atoi(optarg);
                break;
            case 's':
                options->packet_size = atoi(optarg);
                break;
            case '?':
                if (optopt == 'f' || optopt == 'b' || optopt == 'm' || optopt == 's')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            default:
                abort();
        }
    }


    // Check if all mandatory arguments are provided
    if (options->filepath == NULL || options->destination == NULL) {
        printf("Error: Missing mandatory arguments.\n");
        return 1;
    }


    return 0;
}

// Checksum function
// https://www.rfc-editor.org/rfc/rfc4443#section-2.3
// https://www.rfc-editor.org/rfc/rfc2460#section-8.1
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int transfer_data_ip6(char *destination, unsigned char *data, size_t data_len, size_t packet_size, int verbose) {
    const int INTERVAL_MS = 1000; // time between echo requests
    const int PROTO = AF_INET6;
    if (packet_size <= sizeof(struct icmp6_hdr)) {
        fprintf(stderr, "Packet size is smaller than header size, can not send data\n");
        return 1;
    }
    const size_t databytes_per_packet = packet_size - sizeof(struct icmp6_hdr);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PROTO;

    int rv;
    if ((rv = getaddrinfo(destination, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    int sockfd;
    if ((sockfd = socket(PROTO, SOCK_DGRAM, IPPROTO_ICMPV6)) == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in6 dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin6_family = PROTO;
    dest_addr.sin6_addr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

    char packet[packet_size];
    struct icmp6_hdr *icmp_hdr;
    icmp_hdr = (struct icmp6_hdr *)packet;
    icmp_hdr->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp_hdr->icmp6_code = 0;
    uint16_t send_id = 0; // ignored anyway when using DGRAM socket
    icmp_hdr->icmp6_id = send_id;

    uint16_t sequence_number = 0;
    size_t data_sent = 0;
    while (data_sent < data_len) {
        sequence_number++; // overflows are ok
        icmp_hdr->icmp6_seq = htons(sequence_number);

        memcpy(packet + sizeof(struct icmp6_hdr), &data[data_sent], databytes_per_packet);
        icmp_hdr->icmp6_cksum = checksum((unsigned short *)icmp_hdr, packet_size);

        if (verbose) {
            print_packet((struct icmp6_hdr*)packet, packet_size);
        }

        if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
            perror("sendto");
            return 1;
        }

        if (verbose) {
            printf("Ping with sent successfully!\n");
        }

        // Receive the reply
        struct sockaddr_in6 src_addr;
        socklen_t src_addr_len = sizeof(src_addr);
        ssize_t recv_len;

        int with_acks = 1;

        char reply_buff[packet_size];
        if (with_acks) {
            recv_len = recvfrom(sockfd, reply_buff, packet_size, 0, (struct sockaddr *)&src_addr, &src_addr_len);
            if (recv_len < 0) {
                perror("recvfrom");
                return 1;
            } else {
                printf("Received packet of %" PRIu64 " bytes\n", recv_len);
            }
            // Parse the received packet
            struct icmp6_hdr *icmp_reply = (struct icmp6_hdr *)reply_buff;

            if (verbose) {
                print_packet(icmp_reply, packet_size);
                printf("ICMP6 Type: %u\n", icmp_reply->icmp6_type);
                uint16_t recvd_id = icmp_reply->icmp6_id;
                printf("ICMP6 Id: %u\n", recvd_id);
            }

            // TODO: match id, scr and/or data to confirm this is the correct reply
            if (icmp_reply->icmp6_type == ICMP6_ECHO_REPLY) {
                printf("Ping reply received successfully!\n");
            } else {
                printf("Received packet is not a ping reply.\n");
            }
        }

        data_sent += databytes_per_packet;
        if (verbose) {
            printf("Sent %" PRIu64 " of %" PRIu64 " bytes.\n", data_sent, data_len);
        }
    }

    freeaddrinfo(res);
    close(sockfd);

    return 0;

}

int main(int argc, char *argv[]) {
    struct cli_options options;
    if (parse_args(argc, argv, &options) != 0) {
        fprintf(stderr, "Failed parsing optios\n");
        return 1;
    }
    print_options(&options);

    size_t file_size;
    unsigned char *file_contents = read_file(options.filepath, &file_size);
    if (file_contents == NULL) {
        fprintf(stderr, "Error reading file, aborting.\n");
        return 1;
    }

    transfer_data_ip6(options.destination, file_contents, file_size, options.packet_size, 1);

    free(file_contents);

    return 0;
}

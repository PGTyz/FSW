#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// AX.25 地址字段長度
#define AX25_ADDR_LEN 7

// AX.25 封包最大長度
#define AX25_MAX_PKT_LEN 256

// AX.25 地址
typedef struct {
    char callsign[7]; // 呼號
    int ssid; // SSID
} AX25Address;

// AX.25 封包
typedef struct {
    AX25Address destination;
    AX25Address source;
    unsigned char control;
    unsigned char pid;
    unsigned char info[AX25_MAX_PKT_LEN];
    int info_len;
} AX25Packet;

// 設置AX.25地址
void set_ax25_address(unsigned char *addr_field, AX25Address *addr, int last) {
    int i;
    for (i = 0; i < 6; i++) {
        if (i < strlen(addr->callsign)) {
            addr_field[i] = addr->callsign[i] << 1;
        } else {
            addr_field[i] = ' ' << 1;
        }
    }
    if (last == 0) {
        addr_field[6] = (addr->ssid << 1) | 0xE0;
    }
    else {
        addr_field[6] = (addr->ssid << 1) | 0x61;
    }
    
}

// AX.25封包
int ax25_pack(unsigned char *buffer, AX25Packet *pkt) {
    int len = 0;

    set_ax25_address(buffer + len, &pkt->destination, 0);
    len += AX25_ADDR_LEN;


    set_ax25_address(buffer + len, &pkt->source, 1);
    len += AX25_ADDR_LEN;

    buffer[len++] = pkt->control;

    buffer[len++] = pkt->pid;

    memcpy(buffer + len, pkt->info, pkt->info_len);
    len += pkt->info_len;

    return len;
}

int main() {
    AX25Packet pkt;
    unsigned char buffer[AX25_MAX_PKT_LEN];
    int pkt_len;

    strcpy(pkt.destination.callsign, "DESTIN");
    pkt.destination.ssid = 0;

    strcpy(pkt.source.callsign, "SOURCE");
    pkt.source.ssid = 0;

    pkt.control = 0x03; // UI frame

    pkt.pid = 0xF0; // No layer 3 protocol

    const char *msg = "Hello";
    memcpy(pkt.info, msg, strlen(msg));
    pkt.info_len = strlen(msg);

    pkt_len = ax25_pack(buffer, &pkt);

    for (int i = 0; i < pkt_len; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    return 0;
}

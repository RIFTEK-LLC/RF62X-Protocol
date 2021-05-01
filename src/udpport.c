#include "udpport.h"

#ifndef _WIN32
#define INVALID_SOCKET          (-1)
#define SOCKET_ERROR            (-1)
#define TRUE 1
#define FALSE 0
#endif

uint8_t udp_port_init(udp_port_t *udpport)
{
    // Init variabes by default
    udpport->port_num = 0;
    memset(&udpport->input_addr, 0, sizeof(struct sockaddr_in));
    memset(&udpport->output_addr, 0, sizeof(struct sockaddr_in));
    udpport->sock = 0;
    udpport->init_flag = FALSE;
    return TRUE;
}

uint8_t udp_port_cleanup(udp_port_t *udpport)
{
    udp_port_close(udpport);
    return TRUE;
}

uint8_t udp_port_open(udp_port_t *udpport, uint16_t port_number, uint16_t timeout, uint8_t transmit_only)
{
    int ret_val;

    // Check if socket already open.
    if (udpport->port_num != 0)
            return FALSE;

    // Init params in Windows OS.
#if defined(linux) || defined(__linux) || defined(__linux__)
#else
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
        return FALSE;
#endif

    // Init socket.
    udpport->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Close socket in case fail initialization
#if defined(linux) || defined(__linux) || defined(__linux__)
    if (udpport->sock == -1) {
#else
    if (udpport->sock  == INVALID_SOCKET)
    {
        WSACleanup();
#endif
        return FALSE;
    }

    // Init input net atributes.
//    memset((char *)&udpport->input_addr, 0, sizeof(udpport->input_addr));
    udpport->input_addr.sin_family = AF_INET;
    udpport->input_addr.sin_port = htons(port_number);
    //udpport->input_addr.sin_addr.s_addr = INADDR_ANY; // For any source IP.

    // Init output net atributes.
    //memset((char *)&udpport->output_addr, 0, sizeof(udpport->output_addr));
    udpport->output_addr.sin_family = AF_INET;
    udpport->output_addr.sin_port = htons(port_number);
    //udpport->output_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Localhost default.

    // Bing socket if not for tansmission only.
    if (!transmit_only) {
        // Bing socket if not for tansmission only.
#if defined(linux) || defined(__linux) || defined(__linux__)
        ret_val = bind(udpport->sock, (struct sockaddr *)&udpport->input_addr, sizeof(udpport->input_addr));
#else
        ret_val = bind(udpport->sock, (SOCKADDR *)&udpport->input_addr, sizeof(udpport->input_addr));
#endif
#if defined(linux) || defined(__linux) || defined(__linux__)
        if (ret_val < 0) {
#else
        if (ret_val == SOCKET_ERROR) {
#endif
            // Close socket in case fail bind.
#if defined(linux) || defined(__linux) || defined(__linux__)
            close(udpport->sock);
#else
            closesocket(udpport->sock);
            WSACleanup();
#endif
            return FALSE;
        }
    }

    if (timeout != 0)
    {
#if defined(linux) || defined(__linux) || defined(__linux__)
        struct timeval t = {0};
        t.tv_sec = timeout / 1000;
        t.tv_usec = (timeout % 1000) * 1000;
        ret_val = setsockopt(udpport->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
#else
        DWORD t = timeout;
        ret_val = setsockopt(udpport->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(t));
#endif
        // Close socket in case error
        if (ret_val < 0) {
#if defined(linux) || defined(__linux) || defined(__linux__)
            close(udpport->sock);
            return FALSE;
#else
            closesocket(udpport->sock);
            WSACleanup();
            return FALSE;
#endif
        }
    }

#if defined(linux) || defined(__linux) || defined(__linux__)
    int true_flag = 1;
    ret_val = setsockopt(udpport->sock, SOL_SOCKET, SO_BROADCAST, &true_flag, sizeof true_flag);
    if (ret_val < 0)
    {
        close(udpport->sock);
        return FALSE;
    }
#else
    const char true_flag = 1;
    ret_val = setsockopt(udpport->sock, SOL_SOCKET, SO_BROADCAST, &true_flag, sizeof(true_flag));
    // Close socket in case error
    if (ret_val < 0) {
        closesocket(udpport->sock);
        WSACleanup();
        return FALSE;
    }

#endif

    // Remember UDP port number
    udpport->port_num = port_number;
    // Init flag
    udpport->init_flag = TRUE;
    return TRUE;

}

void udp_port_set_dst_ip(udp_port_t *udpport, uint32_t dst_ip)
{
    udpport->output_addr.sin_addr.s_addr = htonl(dst_ip);
}

void udp_port_set_host_ip(udp_port_t *udpport, uint32_t dst_ip)
{
    udpport->input_addr.sin_addr.s_addr = htonl(dst_ip);
}

int udp_port_read_data(udp_port_t *udpport, uint8_t *buf, uint32_t size, struct sockaddr_in *srcSockaddr)
{
    // Check if socket not open.
    if (udpport->port_num == 0)
        return -1;
    // Wait and read data from socket.
    return recvfrom(udpport->sock, (char*)buf, size, 0, (struct sockaddr *)srcSockaddr, NULL);
}

int udp_port_send_data(udp_port_t *udpport, uint8_t *buf, uint32_t size)
{
    // Check if socket not open.
    if (udpport->port_num == 0)
        return -1;
    // Send data.
    return sendto(udpport->sock, (char*)buf, size, 0, (struct sockaddr*) & udpport->output_addr, sizeof(udpport->output_addr));
}

uint8_t udp_port_is_open(udp_port_t *udpport)
{
    return udpport->init_flag;
}

void udp_port_close(udp_port_t *udpport)
{
    // Close socket
    if (udpport->port_num != 0)
    {
#if defined(linux) || defined(__linux) || defined(__linux__)
        close(udpport->sock);
#else
        closesocket(udpport->sock);
        WSACleanup();
#endif
    }
    // Reset flags.
    udpport->port_num = 0;
    udpport->init_flag = FALSE;
}

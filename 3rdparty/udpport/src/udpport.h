#ifndef UDPPORT_H
#define UDPPORT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <Windows.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#endif

typedef struct {
    ///< UDP socket port num.
    uint16_t port_num;
    ///< Input net address structure.
    struct sockaddr_in input_addr;
    ///< Output net address structure.
    struct sockaddr_in output_addr;
    ///< Flag of opened socket.
    uint8_t init_flag;
    ///< Socket
#if defined(linux) || defined(__linux) || defined(__linux__)
    int sock;
#else
    SOCKET sock;
#endif
}udp_port_t;

uint8_t udp_port_init(udp_port_t* udpport);
uint8_t udp_port_cleanup(udp_port_t* udpport);

/**
 * @brief Method to open UDP socket.
 * @param portNumber UDP port number for UDP socket.
 * @param timeout Wait data timeout in milliseconds.
 * @param transmitOnly Only transmission flag. if TRUE then socket wil open only to send data withot registration in OS.
 * @return TRUE in case success or FALSE in case any errors.
 */
uint8_t udp_port_open(
        udp_port_t* udpport,
        uint16_t port_number,
        uint16_t timeout,
        uint8_t transmit_only);

/**
 * @brief Method to set destination IP address (default 255.255.255.255 destination IP).
 * @param dstIP IP address string.
 */
void udp_port_set_dst_ip(
        udp_port_t* udpport,
        uint32_t dst_ip);

/**
 * @brief Method to set destination IP address (default 255.255.255.255 destination IP).
 * @param dstIP IP address string.
 */
void udp_port_set_host_ip(
        udp_port_t* udpport,
        uint32_t dst_ip);

/**
 * @brief Method to read data.
 * @param buf pointer to data buffer to copy data.
 * @param size size of data buffer.
 * @param srcSockaddr pointer to output socket data atributes.
 * @return Number of read bytes or return -1 in case error.
 */
int udp_port_read_data(
        udp_port_t* udpport,
        uint8_t *buf, uint32_t size,
        struct sockaddr_in *srcSockaddr);

/**
 * @brief Method to send data.
 * @param buf pointer to data to send.
 * @param size size of data to send.
 * @return Number of bytes sent or return -1 if UDP socket not open.
 */
int udp_port_send_data(
        udp_port_t* udpport,
        uint8_t *buf,
        uint32_t size);

/**
 * @brief Method to check if UDP socket open.
 * @return TRUE if socke open or FALSE.
 */
uint8_t udp_port_is_open(udp_port_t* udpport);

/**
 * \brief Methos to close UDP socket.
 */
void udp_port_close(udp_port_t* udpport);

#endif // UDPPORT_H

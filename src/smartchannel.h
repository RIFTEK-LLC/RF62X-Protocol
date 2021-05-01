#ifndef SMARTCHANNEL_H
#define SMARTCHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include "smartparser.h"
#include "smartmsg.h"
#include "udpport.h"



typedef struct{
    smart_parser_t smart_parser;

    uint32_t dst_ip_addr;
    uint32_t host_ip_addr;

    udp_port_t smart_sock;

    uint16_t in_udp_port;
    uint16_t out_udp_port;

    uint32_t socket_timeout;

    pthread_mutex_t instance_mutex;
    pthread_mutex_t output_udpport_mutex;
    pthread_mutex_t global_mutex;

    int32_t instance_index;

    pthread_t read_thread;
    uint8_t thread_stop_flag;

    uint8_t* output_packet_data;
    uint16_t max_packet_size;
    uint32_t max_data_size;

}smart_channel;

typedef struct{

    void (*message_status)(int status);
    void (*message_response)(int status);


}smart_callbacks_t;

/**
 * @brief smart_channel_version - Method to get smart channel version.
 * @return The string of transport channel version in form "1.0.0"
 */
char* smart_channel_version();

/**
 * @brief smart_channel_init - Method to init communication channel.
 * @param init_string Initialization string.
 * @return TRUE in case of successful initialization or FALSE.
 */
uint8_t smart_channel_init(
        smart_channel* channel,
        char* init_string);

uint8_t smart_channel_opt_set(
        smart_channel* channel,
        char* opt_name,
        char* val);

uint8_t smart_channel_opt_set_int (
        smart_channel* channel,
        char* opt_name,
        int64_t val);


/**
 * @brief smart_channel_send_data - Method to send data.
 * @param data Pointer to the data to send.
 * @param data_size Size of data to send.
 * @param logic_port Logic port number for data to send.
 * @return TRUE if data was sent or FALSE.
 */
uint8_t smart_channel_send_msg(
        smart_channel* channel,
        smart_msg_t* msg);

/**
 * @brief smart_channel_get_msg - Method to get input data.
 * @param buff Pointer to a buffer for copying data.
 * @param buff_size Size of buffer for copying data.
 * @param input_size Size of readed data.
 * @param logic_port Logic port number of data the data to receive.
 * @param timeout_ms Timeout in Ms to wait for data:
 * timeout_ms == -1 - the method will wait indefinitely until data arrives;
 * timeout_ms == 0  - the method will only check for new data;
 * timeout_ms > 0   - the method will wait specified time.
 * @return
 */
smart_msg_t* smart_channel_get_msg(
        smart_channel* channel,
        int32_t timeout_ms);

/**
 * @brief smart_channel_cleanup - free allocate  memory
 * @return TRUE if smart channel memory free or FALSE.
 */
uint8_t smart_channel_cleanup(smart_channel* channel);


smart_msg_t* smart_create_rqst_msg(char* cmd_name, char* data, uint32_t data_size, char* data_type,
                                   uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
                                   uint32_t timeout,
                                   smart_answ_callback answ,
                                   smart_timeout_callback timeout_clb,
                                   smart_free_callback free_clb);
/**
 * @brief smart_get_result_to_rqst_msg - Method to get result to msg-request.
 * @param smart_channel Pointer to the channel.
 * @param smart_msg_t Pointer to the rqst_msg.
 * @return Pointer to the result, or NULL.
 */
void *smart_get_result_to_rqst_msg(smart_channel* channel,
                                   smart_msg_t* rqst_msg,
                                   uint32_t timeout);

smart_msg_t* smart_create_answ_msg(smart_msg_t* rqst_msg, char *data, uint32_t data_size, char* data_type,
                                   uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
                                   uint32_t timeout,
                                   smart_answ_callback answ_clb,
                                   smart_timeout_callback timeout_clb,
                                   smart_free_callback free_clb);

void smart_cleanup_msg(smart_msg_t* msg);

#endif // SMARTCHANNEL_H

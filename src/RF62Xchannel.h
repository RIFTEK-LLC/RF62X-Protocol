#ifndef RF62X_CHANNEL_H
#define RF62X_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include "RF62Xparser.h"
#include "RF62Xmsg.h"

#include "udpport.h"


typedef struct{
    RF62X_parser_t RF62X_parser;

    uint32_t dst_ip_addr;
    uint32_t host_ip_addr;

    udp_port_t RF62X_sock;

    uint16_t host_udp_port;
    uint16_t dst_udp_port;

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

}RF62X_channel;

typedef struct{

    void (*message_status)(int status);
    void (*message_response)(int status);


}RF62X_callbacks_t;

/**
 * @brief RF62X_channel_version - Method to get RF62X channel version.
 * @return The string of transport channel version in form "1.0.0"
 */
char* RF62X_channel_version();

/**
 * @brief RF62X_channel_init - Method to init communication channel.
 * @param init_string Initialization string.
 * @return TRUE in case of successful initialization or FALSE.
 */
uint8_t RF62X_channel_init(
        RF62X_channel* channel,
        char* init_string);

uint8_t RF62X_channel_opt_set(
        RF62X_channel* channel,
        char* opt_name,
        char* val);

uint8_t RF62X_channel_opt_set_int (
        RF62X_channel* channel,
        char* opt_name,
        int64_t val);


/**
 * @brief RF62X_channel_send_data - Method to send data.
 * @param data Pointer to the data to send.
 * @param data_size Size of data to send.
 * @param logic_port Logic port number for data to send.
 * @return TRUE if data was sent or FALSE.
 */
uint8_t RF62X_channel_send_msg(
        RF62X_channel* channel,
        RF62X_msg_t* msg);

/**
 * @brief RF62X_channel_get_msg - Method to get input data.
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
RF62X_msg_t* RF62X_channel_get_msg(
        RF62X_channel* channel,
        int32_t timeout_ms);

/**
 * @brief RF62X_channel_cleanup - free allocate  memory
 * @return TRUE if RF62X channel memory free or FALSE.
 */
uint8_t RF62X_channel_cleanup(RF62X_channel* channel);


RF62X_msg_t* RF62X_create_rqst_msg(char* cmd_name, char* data, uint32_t data_size, char* data_type,
                                   uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
                                   uint32_t timeout,
                                   RF62X_answ_callback answ,
                                   RF62X_timeout_callback timeout_clb,
                                   RF62X_free_callback free_clb);
/**
 * @brief RF62X_get_result_to_rqst_msg - Method to get result to msg-request.
 * @param RF62X_channel Pointer to the channel.
 * @param RF62X_msg_t Pointer to the rqst_msg.
 * @return Pointer to the result, or NULL.
 */
void *RF62X_get_result_to_rqst_msg(RF62X_channel* channel,
                                   RF62X_msg_t* rqst_msg,
                                   uint32_t timeout);

RF62X_msg_t* RF62X_create_answ_msg(RF62X_msg_t* rqst_msg, char *data, uint32_t data_size, char* data_type,
                                   uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
                                   uint32_t timeout,
                                   RF62X_answ_callback answ_clb,
                                   RF62X_timeout_callback timeout_clb,
                                   RF62X_free_callback free_clb);

void RF62X_cleanup_msg(RF62X_msg_t* msg);

#endif // RF62X_CHANNEL_H

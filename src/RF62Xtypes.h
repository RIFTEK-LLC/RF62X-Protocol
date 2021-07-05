#ifndef RF62X_PROTOCOL_TYPES_H
#define RF62X_PROTOCOL_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "udpport.h"
#include "pthread.h"

typedef int8_t (*RF62X_answ_callback)(
        char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg);

typedef int8_t (*RF62X_timeout_callback)(void* rqst_msg);

typedef int8_t (*RF62X_free_callback)(void* rqst_msg);

typedef struct
{
    char type[64];
    char cmd_name[256];
    char container_type[64];

    uint8_t check_crc_flag;
    uint8_t confirmation_flag;
    uint8_t one_answ_flag;
    uint8_t wait_answ_flag;

    char* data;
    uint32_t data_size;

    RF62X_answ_callback _answ_clb;
    RF62X_timeout_callback _timeout_clb;
    RF62X_free_callback _free_clb;

    uint64_t _msg_uid;
    uint64_t _device_id;
    uint64_t _uid;
    uint32_t _sending_time;
    uint32_t _timeout;
    uint32_t _resends;

    uint16_t state;            ///< Data receiver acknowledgment flag

    void* result;
    pthread_mutex_t* result_mutex;
}RF62X_msg_t;

typedef enum{
    RF62X_MSG_EMPTY = 0, // Empty msg

    RF62X_MSG_WAIT_DECODING = 1,
    RF62X_MSG_WAIT_ENCODING = 2,
    RF62X_MSG_WAIT_CONFIRMATION = 4,
    RF62X_MSG_WAIT_ANSW = 8,
    RF62X_MSG_WAIT_READING = 16,

    RF62X_MSG_TIMEOUT = 32,

    RF62X_MSG_DECODED = 64,
    RF62X_MSG_ENCODED = 128,
    RF62X_MSG_CONFIRMED = 256,
    RF62X_MSG_ANSWERED = 512,
    RF62X_MSG_READ = 1024
}RF62X_MSG_STATE;

/**
 * @brief Structure for output data.
 */
typedef struct {
    RF62X_msg_t* msg;         ///< Pointer to buffer for output data
    uint32_t data_pos;         ///< Current position of the data to send in the packet
} RF62X_parser_output_msg_t;

/**
 * @brief Structure for output data.
 */
typedef struct {
    RF62X_msg_t* msg;         ///< Pointer to buffer for output data
    uint8_t* mask;             ///< Pointer to mask of input data (A mask is required to account for the receipt of data)
    uint32_t received_size;    ///< Current data size of input data
    uint32_t data_pos;         ///< Current position of the data to send in the packet
} RF62X_parser_input_msg_t;

/**
 * @brief Structure for output data.
 */
typedef struct {
    uint8_t* data;              ///< Pointer to buffer for output data
    uint32_t data_pos;          ///< Current position of the data to send in the packet
    uint32_t data_size;         ///< Output data size
    uint32_t data_id;           ///< Data ID (Automatically assigned to new data)
    uint8_t is_data_confirmed;	///< Data receiver acknowledgment flag
} RF62X_parser_output_data_t;

// Input data structure
typedef struct {
    uint8_t* data;              ///< Pointer to buffer for input data
    uint8_t* mask;              ///< Pointer to mask of input data (A mask is required to account for the receipt of data)
    uint32_t chain_size;        ///< Full data size of input data
    uint32_t data_size;         ///< Current data size of input data
    uint32_t data_pos;          ///< Current position of received data in data buffer
    uint32_t msg_uid;           ///< Data ID of received data
    uint32_t uid;               ///< Data ID of received data
    char* cmd_name;
} RF62X_parser_input_data;

typedef struct {
    ///< Buffer of output data. Each element has 2 buffers (double buffering).
    RF62X_parser_output_msg_t* output_msg_buffer;
    ///< Index of current output data in buffer for each logic port.
    uint32_t output_msg_index;

    ///< Buffer of output data. Each element has 2 buffers (double buffering).
    RF62X_parser_input_msg_t* input_msg_buffer;
    ///< Index of current output data in buffer for each logic port.
    uint32_t input_msg_index;


    ///< Buffer of output data. Each element has 2 buffers (double buffering).
    RF62X_parser_output_data_t* output_data;
    pthread_mutex_t output_msg_buff_mutex;
    ///< Index of current output data in buffer for each logic port.
    uint32_t output_data_index;
    ///< ID of current outout data for each logic port.
    uint8_t output_data_id;
    ///< Data ID of current output data.
    char output_data_cmd_name[256];

    ///< Buffer for input data. Each element has RF62X_PARSER_INPUT_BUFFER_QUEUE buffers (double buffering).
    RF62X_parser_input_data* input_data;
    ///< Index of current input data in buffer for each logic port.
    uint32_t input_data_index;

    ///< Data ID of ready input data.
    char input_data_cmd_name[256];
    ///< Mutex to protect input data buffer.
    pthread_mutex_t input_msg_buff_mutex;

    ///< Mutexes for conditional variabes.
    pthread_mutex_t input_data_cond_var_mutex;
    pthread_cond_t input_data_cond_var;
    pthread_mutex_t input_wait_confirm_var_mutex;
    pthread_cond_t input_wait_confirm_cond_var;
    ///< Flags for conditional variabes.
    uint8_t input_data_cond_var_flag;
    uint8_t input_wait_confirm_cond_var_flag;
    pthread_mutex_t instance_mutex;

    ///< Maximum input and output data size. In accordance with this value, memory is allocated for data buffers. Default = 1024 bytes.
    uint32_t max_data_size;
    ///< Maximum input and output packet size. In accordance with this value, memory is allocated for data buffers. Default = 6220800 bytes.
    uint16_t max_packet_size;
    ///< Maximum input and output packet size. In accordance with this value, memory is allocated for data buffers. Default = 6220800 bytes.
    uint32_t host_device_uid;

    ///< Buffer for requested lost data.
    uint8_t* detected_lost_data;
    ///< Size of requested lost data.
    uint32_t detected_lost_data_size;
    ///< Start position of requested lost data in output data buffer.
    uint32_t detected_lost_data_pos;
    ///< Size of output data.
    uint32_t lost_full_data_size;
    ///< Data ID of requested lost data.
    uint8_t detected_lost_data_id;
    ///< Logic port of requested lost data.
    uint8_t detected_lost_data_logic_port;

    ///< Buffer for serial data for packets.
    uint8_t* packet_data_buff;
    ///< Current position in serial data buffer.
    uint32_t packet_data_pos;
    ///< Mutex to protect serial data buffer.
    pthread_mutex_t packet_data_mutex;
    ///< Size of serial packet data.
    uint16_t serial_packet_size;
    ///< Flag for detected inpud data part of packets.
    uint8_t data_packet_flag;

    ///< Buffer for LOST_DATA_REQUEST packet.
    uint8_t* lost_data_request_packet;
    ///< Buffer for DATA_CONFIRMATION packet.
    uint8_t* data_confirmation_packet;

} RF62X_parser_t;

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

}RF62X_channel_t;

#endif // RF62X_PROTOCOL_TYPES_H

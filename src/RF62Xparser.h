#ifndef RF62XPARSER_H
#define RF62XPARSER_H

#include "RF62Xmsg.h"

#include <stddef.h>
#include <stdint.h>


#include "pthread.h"

// Default params
#define RF62X_PARSER_DEFAULT_MAXIMUM_PACKET_SIZE 1024	///< Default maximum paket size
#define RF62X_PARSER_DEFAULT_MAXIMUM_DATA_SIZE 6220800	///< Default maximum data size
#define RF62X_PARSER_DEFAULT_WAIT_CONFIRM_TIMEOUT 5    ///< Default confirmation timeout

#define RF62X_PARSER_MAJOR_PROTOCOL_VERSION 1			///< Major version of RF62X protocol
#define RF62X_PARSER_MINOR_PROTOCOL_VERSION 4			///< Monir version of RF62X protocol
#define RF62X_PARSER_PATCH_PROTOCOL_VERSION 2			///< Patch version of RF62X protocol
#define RF62X_PARSER_INPUT_BUFFER_QUEUE 10				///< Num logic ports
#define RF62X_PARSER_OUTPUT_BUFFER_QUEUE 10
#define RF62X_PARSER_NUM_LOGIC_PORTS 256				///< Num logic ports

// Return statuses
#define RF62X_PARSER_RETURN_STATUS_NO_DATA 0
#define RF62X_PARSER_RETURN_STATUS_DATA_READY 1
#define RF62X_PARSER_RETURN_STATUS_LOST_DATA_DETECTED 2
#define RF62X_PARSER_RETURN_STATUS_DATA 3
#define RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION 4
#define RF62X_PARSER_RETURN_STATUS_LOST_DATA_REQUEST 5
#define RF62X_PARSER_RETURN_STATUS_DATA_CONFIRMATION 6
#define RF62X_PARSER_RETURN_STATUS_PACKET_ERROR -1
#define RF62X_PARSER_RETURN_STATUS_PARAMS_ERROR -2
#define RF62X_PARSER_RETURN_STATUS_INCORRECT_PROTOCOL_VERSION -3
#define RF62X_PARSER_RETURN_STATUS_NO_PERMISSION -4
#define RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT -5
#define RF62X_PARSER_RETURN_STATUS_DATA_ERROR -6
#define RF62X_PARSER_RETURN_STATUS_NO_FREE_BUFFER -7


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
    uint32_t src_device_uid;

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

    char* logic_port_name_list[RF62X_PARSER_NUM_LOGIC_PORTS];
} RF62X_parser_t;

/**
 * @brief RF62X_parser_init - Method to init communication parser.
 * @param init_string Initialization string.
 * @return TRUE in case of successful initialization or FALSE.
 */
uint8_t RF62X_parser_init(RF62X_parser_t* parser, char* init_string);

/**
 * @brief RF62X_parser_cleanup - free allocate memory
 * @return TRUE if RF62X parser memory free or FALSE.
 */
uint8_t RF62X_parser_cleanup(RF62X_parser_t* parser);

/**
 * @brief Method to add new output data to encode.
 * @details Must be called before encoding new data.
 * @param data Pointer to new data.
 * @param data_size Size of new data.
 * @param logic_port Logic port for new data.
 * @return TRUE if new data copying is successful or FALSE
 *         when data_size == 0 or data_size > maximum data size
 *         setted in Init(...) method.
 */
uint8_t RF62X_parser_add_msg(RF62X_parser_t* parser, RF62X_msg_t* msg);

/**
 * @brief Method to encode DATA packet.
 * @details The method forms DATA packets. Before creating packages with new data, the AddData(...) method must be called.
 *          After the encoding of all packets with new data, the encoding of data begins from the beginning.
 * @param packetData Pointer to buffer to copy packet data. Should have minimum size of maximumPacketSize
 *                   specified in Init(...) method.
 * @param packetSize Output size of generated packet.
 * @param logicPort Logic port of encoded data.
 * @return Method returns the following values:
 *         (0) if there are no data for encoding or encoded data already confirmed by data receiver;
 *         (1) if full data was encoded. The next time the method is called, encoding will begin from the beginning;
 *         (3) DATA packet was encoded.
 */
int32_t RF62X_parser_encode_msg(RF62X_parser_t* parser,
    uint8_t* packet_data,
    uint16_t* packet_size);

/**
 * @brief Method to process input packet.
 * @param packetData Pointer to input packet data.
 * @param packetSize Size of input packet.
 * @param msg_uid Output value of msg id of input packet.
 * @return Method returns follow values:
 *         (-1) if there is an error in the packet data;
 *         (-3) if the protocol version of the received packet is different from the current protocol version;
 *         (1)  if the packet DATA was successfully processed and FULL DATA WAS RECEIVED;
 *         (2)  if lost data was detected. You can get LOST_DATA_REQUEST packet via GetLostDataRequestPacket(...) method;
 *         (3)  if the packet DATA was successfully processed;
 *         (5)  if the packet LOST_DATA_REQUEST was successfully processed. You can get lost data packet to
 *              send via EncodeLostDataPacket(...) method;
 *         (6)  if the packet DATA_CONFIRMATION was successfully processed.
 */
int32_t RF62X_parser_decode_msg(RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t packet_size);

/**
 * @brief Method to get input data.
 * @details The method will allow you to check the availability of received data, and also
 *          allows you to wait for incoming data if they do not already exist. The method
 *          allows you to read the received data only once.
 * @param data Pointer to buffer to copy data.
 * @param dataBuffSize Size of data buffer.
 * @param dataSize Received data size.
 * @param logicPort Logic port of requested data. Data availability is checked only for the specified logic port.
 * @param timeout Timeout to wait for data. It has different meanings for different values:
 *                (-1) We are waiting for new data endlessly until it arrives;
 *                (0)  We do not wait for data but only check if there is new data;
 *                (>0) We are waiting for the data indicated time. Time is indicated in milliseconds.
 * @return TRUE if there is new data and it was successfully copied or FALSE.
 */
RF62X_msg_t* RF62X_parser_get_msg(RF62X_parser_t* parser, int32_t timeout);


/**
 * @brief Method to get LOST_DATA_REQUEST packet.
 * @details The LOST_DATA_REQUEST packet is generated automatically when it detects lost data
 *          in a method DecodePacket(...).
 * @param packetData Pointer to buffer to copy packet data. Should have minimum size of 19 bytes.
 * @param packetSize Output size of generated packet. Always has value of 19 bytes.
 */
void RF62X_parser_get_lost_data_request_packet(RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t* packet_size);

/**
 * @brief Method to get DATA_CONFIRMATION packet.
 * @details The DATA_CONFIRMATION packet is generated automatically when it detects new input data
 *          in the method DecodePacket(...).
 * @param packetData Pointer to buffer to copy packet data. Should have minimum size of 19 bytes.
 * @param packetSize Output size of generated packet. Always has value of 19 bytes.
 */
void RF62X_parser_get_msg_confirmation_packet(RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t* packet_size);

/**
 * @brief Method to encode DATA packets with requested lost data.
 * @details When a request for retransmission of lost data is received, the method DecodePacket(...) or
 *          DecodeSerialData(...) copies the lost data to the buffer for sending. When the method is
 *          called, DATA packets with lost data will be encoded.
 * @param packetSize Output size of generated packet.
 * @param logicPort Logic port of encoded data.
 * @return (0) if there are no data for encoding or return (3) if DATA packet was encoded.
 */
int32_t RF62X_parser_encode_lost_data_packet(RF62X_parser_t* parser,
    uint8_t* packet_data,
    uint16_t* packet_size);

uint8_t RF62X_parser_opt_set(RF62X_parser_t* parser, char *opt_name, char *val);

#endif // RF62XPARSER_H

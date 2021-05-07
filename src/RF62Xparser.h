#ifndef RF62X_PARSER_H
#define RF62X_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "RF62Xtypes.h"

// Default params
#define RF62X_PARSER_DEFAULT_MAXIMUM_PACKET_SIZE 1024	///< Default maximum paket size
#define RF62X_PARSER_DEFAULT_MAXIMUM_DATA_SIZE 6220800	///< Default maximum data size
#define RF62X_PARSER_DEFAULT_WAIT_CONFIRM_TIMEOUT 50    ///< Default confirmation timeout

#define RF62X_PARSER_INPUT_BUFFER_QUEUE 10				///< Num logic ports
#define RF62X_PARSER_OUTPUT_BUFFER_QUEUE 10

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

/**
 * @brief RF62X_parser_init - Method to init RF62X communication parser.
 * @param parser Ptr(not NULL) to RF62X_parser_t for initialization.
 * @param init_string Initialization string.
 * @return TRUE in case of successful initialization or FALSE.
 */
uint8_t RF62X_parser_init(
        RF62X_parser_t* parser,
        char* init_string);

/**
 * @brief RF62X_parser_cleanup - Cleanup resources allocated for RF62X_parser_t
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @return TRUE if RF62X channel memory free or FALSE.
 */
uint8_t RF62X_parser_cleanup(
        RF62X_parser_t* parser);

/**
 * @brief RF62X_parser_opt_set - Set RF62X_parser option
 * @param channel Ptr to RF62X_channel (not NULL).
 * @param opt_name Option name
 * @param val New value for opt_name
 * @return TRUE on successful change or FALSE.
 */
uint8_t RF62X_parser_opt_set(
        RF62X_parser_t* parser,
        char *opt_name,
        char *val);

/**
 * @brief RF62X_parser_add_msg - Method to add new output msg to encode.
 * @details Must be called before encoding by RF62X_parser_encode_msg method.
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @param msg Ptr(not NULL) to new output msg to encode
 * @return TRUE if new msg added successfully or FALSE
 */
uint8_t RF62X_parser_add_msg(
        RF62X_parser_t* parser,
        RF62X_msg_t* msg);

/**
 * @brief RF62X_parser_encode_msg - Method to encode DATA packet.
 * @details The method forms msg packets. Before creating packages with new msg,
 * the RF62X_parser_add_msg(...) method must be called.
 * After the encoding of all packets with a new msg, the data encoding ends.
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @param packet_data Pointer to buffer to copy packet data.
 * Should have minimum size of parser->max_packet_size (specified in
 * RF62X_parser_init(...) method in init_string).
 * @param packet_size Output size of generated packet.
 * @return Method returns one of the RF62X_PARSER_RETURN_STATUS statuses
 */
int32_t RF62X_parser_encode_msg(
        RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t* packet_size);

/**
 * @brief RF62X_parser_decode_msg - Method to process input packet.
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @param packet_data Pointer to input packet data.
 * @param packet_size Size of input packet.
 * @return Method returns one of the RF62X_PARSER_RETURN_STATUS statuses
 */
int32_t RF62X_parser_decode_msg(
        RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t packet_size);

/**
 * @brief RF62X_parser_get_msg - Method to get input data.
 * @details The method will allow you to check the availability of
 * received RF62X_msg_t, and also allows you to wait for incoming messages
 * if they do not already exist. The method allows you to read the received
 * messages only once.
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @param timeout Timeout to wait for msg. It has different meanings for
 * different values:
 * timeout_ms == -1 - the method will endlessly wait for new data until it arrives;
 * timeout_ms == 0  - the method will not wait for data but only check;
 * timeout_ms > 0   - the method will wait specified time
 * @return Ptr to RF62X_msg_t if there is new msg or NULL.
 */
RF62X_msg_t* RF62X_parser_get_msg(
        RF62X_parser_t* parser,
        int32_t timeout_ms);


/**
 * @brief RF62X_parser_get_msg_confirmation_packet - Method to get
 * DATA_CONFIRMATION packet.
 * @details The DATA_CONFIRMATION packet is generated automatically when it
 * detects new input data in the method RF62X_parser_decode_msg(...).
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @param packet_data Pointer to buffer to copy packet data.
 * Should have minimum size of parser->max_packet_size (specified in
 * RF62X_parser_init(...) method in init_string).
 * @param packet_size Output size of generated packet.
 */
void RF62X_parser_get_msg_confirmation_packet(
        RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t* packet_size);

/** TODO:
 * @brief RF62X_parser_get_lost_data_request_packet - Method to get
 * LOST_DATA_REQUEST packet.
 * @details The LOST_DATA_REQUEST packet is generated automatically when it
 * detects lost msg in a method RF62X_parser_decode_msg(...).
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @param packet_data Pointer to buffer to copy packet data.
 * Should have minimum size of parser->max_packet_size (specified in
 * RF62X_parser_init(...) method in init_string).
 * @param packet_size Output size of generated packet.
 */
void RF62X_parser_get_lost_data_request_packet(
        RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t* packet_size);

/** TODO:
 * @brief RF62X_parser_encode_lost_data_packet - Method to encode DATA packets
 * with requested lost data.
 * @details When a request for retransmission of lost data is received, the
 * method RF62X_parser_decode_msg(...) copies the lost data to the buffer for
 * sending. When method is called, DATA packets with lost data will be encoded.
 * @param parser Ptr(not NULL) to RF62X_parser_t
 * @param packet_data Pointer to buffer to copy packet data.
 * Should have minimum size of parser->max_packet_size (specified in
 * RF62X_parser_init(...) method in init_string).
 * @param packet_size Output size of generated packet.
 * @return (0) if there are no data for encoding or return (3) if DATA packet
 * was encoded.
 */
int32_t RF62X_parser_encode_lost_data_packet(
        RF62X_parser_t* parser,
        uint8_t* packet_data,
        uint16_t* packet_size);

#endif // RF62X_PARSER_H

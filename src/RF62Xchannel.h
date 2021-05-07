#ifndef RF62X_CHANNEL_H
#define RF62X_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

#include "RF62Xtypes.h"

/**
 * @brief RF62X_channel_version - Method to get RF62X channel version.
 * @return The string of RF62X channel version in form "1.0.0"
 */
char* RF62X_channel_version();

/**
 * @brief RF62X_channel_init - Method to init RF62X communication channel.
 * @param channel Ptr(not NULL) to RF62X_channel_t for initialization.
 * @param init_string Initialization string.
 * @return TRUE in case of successful initialization or FALSE.
 */
uint8_t RF62X_channel_init(
        RF62X_channel_t* channel,
        char* init_string);

/**
 * @brief RF62X_channel_cleanup - Cleanup resources allocated for RF62X_channel_t
 * @param channel Ptr(not NULL) to RF62X_channel
 * @return TRUE if RF62X channel memory free or FALSE.
 */
uint8_t RF62X_channel_cleanup(
        RF62X_channel_t* channel);

/**
 * @brief RF62X_channel_opt_set - Set RF62X_channel_t option
 * @param channel Ptr to RF62X_channel_t (not NULL).
 * @param opt_name Option name
 * @param val New value for opt_name
 * @return TRUE on successful change or FALSE.
 */
uint8_t RF62X_channel_opt_set(
        RF62X_channel_t* channel,
        char* opt_name,
        char* val);

/**
 * @brief RF62X_channel_send_msg - Method to send message.
 * @param channel RF62X_channel_t ptr(not NULL) from which the msg will be sent
 * @param msg Message to send
 * @return TRUE if message was sent or FALSE.
 */
uint8_t RF62X_channel_send_msg(
        RF62X_channel_t* channel,
        RF62X_msg_t* msg);

/**
 * @brief RF62X_channel_get_msg - Method to get input message.
 * @param channel RF62X_channel_t ptr(not NULL) from which msg will be received
 * @param timeout_ms Timeout in ms to wait for message:
 * timeout_ms == -1 - the method will wait indefinitely until message arrives;
 * timeout_ms == 0  - the method will only check for new message;
 * timeout_ms > 0   - the method will wait specified time.
 * @return RF62X_msg_t ptr on successful received or NULL
 */
RF62X_msg_t* RF62X_channel_get_msg(
        RF62X_channel_t* channel,
        int32_t timeout_ms);


/**
 * @brief RF62X_create_rqst_msg - Function for creating request messages.
 * @param cmd_name Logical port/path where data will be send
 * @param payload Ptr to data to be sent
 * @param payload_size Data size to send
 * @param data_type Type of packaging of the sent data (mpack, json, blob..)
 * @param is_check_crc CRC check flag
 * @param is_confirmation ON/OFF confirmation (best used for sending big data)
 * @param is_one_answ Wait one answer per request
 * @param waiting_time Time to wait for a response (rqst msg lifetime)
 * @param answ_clb Callback ptr is called when data for rqst has been received
 * if answ_clb == NULL - the response to the request will be ignored.
 * @param timeout_clb Callback ptr is called when the request timed out.
 * @param free_clb Callback ptr is called to clear the data when response
 * has been received but not read.
 * @return RF62X_msg_t ptr on successful creating or NULL
 */
RF62X_msg_t* RF62X_create_rqst_msg(
        char* cmd_name, char* payload, uint32_t payload_size, char* data_type,
        uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
        uint32_t waiting_time,
        RF62X_answ_callback answ,
        RF62X_timeout_callback timeout_clb,
        RF62X_free_callback free_clb);

/**
 * @brief RF62X_create_answ_msg - Function for creating message reply.
 * @param rqst_msg Pointer to the received request msg to be answered
 * @param payload Ptr to data to be sent
 * @param payload_size Data size to send
 * @param data_type Type of packaging of the sent data (mpack, json, blob..)
 * @param is_check_crc CRC check flag
 * @param is_confirmation ON/OFF confirmation (best used for sending big data)
 * @param is_one_answ Wait one answer per message reply
 * @param waiting_time Time to wait for a response (message reply lifetime)
 * @param answ_clb Callback ptr is called when data for reply has been received
 * if answ_clb == NULL - the response to the reply will be ignored.
 * @param timeout_clb Callback ptr is called when the reply timed out.
 * @param free_clb Callback ptr is called to clear the data when response
 * has been received but not read.
 * @return RF62X_msg_t ptr on successful creating or NULL
 */
RF62X_msg_t* RF62X_create_answ_msg(
        RF62X_msg_t* rqst_msg, char *payload, uint32_t payload_size, char* data_type,
        uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
        uint32_t timeout,
        RF62X_answ_callback answ_clb,
        RF62X_timeout_callback timeout_clb,
        RF62X_free_callback free_clb);

/**
 * @brief RF62X_find_result_to_rqst_msg - Method to find/wait some results for
 * request message from RF62X_answ_callback.
 * If the user wants return any results data from RF62X_answ_callback to main
 * thread, he can write to rqst_msg->result field (RF62X_answ_callback argument)
 * @param RF62X_channel_t Pointer to the channel.
 * @param RF62X_msg_t Pointer to the rqst_msg.
 * @param timeout_ms Timeout in ms to find/wait for result:
 * timeout_ms == -1 - the method will wait indefinitely until message arrives;
 * timeout_ms == 0  - the method will only check for new message;
 * timeout_ms > 0   - the method will wait specified time.
 * @return Pointer to the result data, or NULL.
 */
void* RF62X_find_result_to_rqst_msg(
        RF62X_channel_t* channel,
        RF62X_msg_t* rqst_msg,
        uint32_t timeout_ms);

void RF62X_cleanup_msg(RF62X_msg_t* msg);

#endif // RF62X_CHANNEL_H

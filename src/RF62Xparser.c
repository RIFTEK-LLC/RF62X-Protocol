#define _CRT_SECURE_NO_WARNINGS
#include "RF62Xparser.h"
#include "RF62Xchannel.h"
#include "mpack/mpack.h"
#include "utils.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <winsock.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

typedef int BOOL;
typedef int SOCKET;

#define INVALID_SOCKET          (-1)
#define SOCKET_ERROR            (-1)
#define TRUE 1
#define FALSE 0
#endif

typedef struct
{
    char* key;
    char* value;
}RF62X_parser_init_param_t;

uint8_t RF62X_parser_init(RF62X_parser_t* parser,
                          char *init_string)
{
    // Preparation RF62X_parser for initialization
    memset(parser, 0, sizeof (RF62X_parser_t));
    parser->packet_data_buff = NULL;
    parser->packet_data_pos = 0;
    parser->data_packet_flag = FALSE;
    parser->serial_packet_size = 0;
    parser->detected_lost_data = NULL;
    parser->detected_lost_data_size = 0;
    parser->detected_lost_data_pos = 0;
    parser->lost_full_data_size = 0;
    parser->detected_lost_data_id = 0;
    parser->detected_lost_data_logic_port = 0;

    pthread_mutex_init(&parser->instance_mutex, NULL);

    pthread_cond_init(&parser->input_data_cond_var, NULL);
    pthread_mutex_init(&parser->input_data_cond_var_mutex, NULL);

    pthread_cond_init(&parser->input_wait_confirm_cond_var, NULL);
    pthread_mutex_init(&parser->input_wait_confirm_var_mutex, NULL);

    pthread_mutex_init(&parser->output_msg_buff_mutex, NULL);
    pthread_mutex_init(&parser->input_msg_buff_mutex, NULL);



    // TODO: Init LOST_DATA_REQUEST packet data

    // TODO: Init DATA_CONFIRMATION packet data

    // TODO: Init packet header buffer

    // Read init_string and Set params to variabes.
    if (strlen(init_string) > 0)
    {
        // Parse parameters.
        uint32_t _str_len = (uint32_t)strlen(init_string) + 1;
        char* _init_string = calloc(_str_len, sizeof(char));

        memcpy(_init_string, init_string, _str_len);

        char *token;
        int param_count = 0;
        token = strtok(_init_string, "--");
        while (token != NULL)
        {
            param_count++;
            token=strtok(NULL,"--");
        }

        RF62X_parser_init_param_t* params = calloc(param_count, sizeof (RF62X_parser_init_param_t));

        memcpy(_init_string, init_string, _str_len);
        token = strtok(_init_string, " "); uint32_t token_len = 0;
        for (int i = 0; i < param_count; i++)
        {
            token_len = (uint32_t)strlen(token) + 1;
            params[i].key = calloc(token_len, sizeof (char));
            memcpy(params[i].key, token, token_len);

            token = strtok(NULL, " "); token_len = (uint32_t)strlen(token) + 1;
            params[i].value = calloc(token_len, sizeof (char));
            memcpy(params[i].value, token, token_len);

            token = strtok(NULL, " ");
        }

        // Set params to variabes.
        for(int i = 0; i < param_count; i++)
        {
            RF62X_parser_opt_set(parser, params[i].key, params[i].value);
            free(params[i].key); params[i].key = NULL;
            free(params[i].value); params[i].value = NULL;
        }

        free(_init_string);
        free(params);

        // Init output data structures
        parser->output_data = NULL;
        parser->output_data_index = 0;
        parser->output_data_id = 0;

        // Init output data structures
        parser->output_msg_buffer = calloc(RF62X_PARSER_OUTPUT_BUFFER_QUEUE, sizeof (RF62X_parser_output_msg_t));
        for(int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
        {
            parser->output_msg_buffer[i].msg = calloc(1, sizeof (RF62X_msg_t));
            parser->output_msg_buffer[i].msg->state = RF62X_MSG_EMPTY;
            parser->output_msg_buffer[i].msg->result = NULL;
            parser->output_msg_buffer[i].data_pos = 0;
        }
        parser->output_msg_index = RF62X_PARSER_OUTPUT_BUFFER_QUEUE - 1;
        // Check of initialization of output msg buffer.

        parser->input_msg_buffer = calloc(RF62X_PARSER_INPUT_BUFFER_QUEUE, sizeof (RF62X_parser_input_msg_t));
        // Check data input data structure initialization
        for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
        {
            parser->input_msg_buffer[i].msg = calloc(1, sizeof (RF62X_msg_t));
            parser->input_msg_buffer[i].msg->state = RF62X_MSG_EMPTY;
            parser->input_msg_buffer[i].msg->result = NULL;
            parser->input_msg_buffer[i].data_pos = 0;
        }
        parser->input_msg_index = RF62X_PARSER_INPUT_BUFFER_QUEUE - 1;

        // Init input data structures
        parser->input_data = NULL;
        parser->input_data_index = 0;

        parser->input_data_cond_var_flag = FALSE;
        parser->input_wait_confirm_cond_var_flag = FALSE;

        return TRUE;
    }

    return FALSE;
}


uint8_t RF62X_parser_opt_set(RF62X_parser_t* parser, char *opt_name, char *val)
{
    if (0 == strcmp(opt_name, "--max_packet_size"))
    {
        string_to_uint16(val, &parser->max_packet_size);
    }
    else if (0 == strcmp(opt_name, "--max_data_size"))
    {
        string_to_uint32(val, &parser->max_data_size);
    }
    else if (0 == strcmp(opt_name, "--host_device_uid"))
    {
        string_to_uint32(val, &parser->host_device_uid);
    }

    return TRUE;

}

int32_t RF62X_parser_encode_lost_data_packet(RF62X_parser_t *parser, uint8_t *packet_data, uint16_t *packet_size)
{
    (void)parser;
    (void)packet_data;
    (void)packet_size;
    return FALSE;
}

void RF62X_parser_get_msg_confirmation_packet(RF62X_parser_t *parser, uint8_t *packet_data, uint16_t *packet_size)
{
    const int lock_rv = pthread_mutex_lock(&parser->input_msg_buff_mutex);
    if (lock_rv)
    {
        error_pthread_mutex_lock(lock_rv);
        return;
    }

    // Поиск сообщений, требующих подтверждение
    for (uint16_t i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
    {
        RF62X_msg_t* msg = parser->input_msg_buffer[i].msg;
        if (msg->state & RF62X_MSG_WAIT_CONFIRMATION)
        {
            // Create FULL DATA packet for measurement SIZE of data packet
            mpack_writer_t writer;
            char* send_packet = NULL;
            size_t bytes = 0;				///< Number of msg bytes.
            mpack_writer_init_growable(&writer, &send_packet, &bytes);

            mpack_start_map(&writer, 1);
            {
                mpack_write_cstr(&writer, "ack_uid");
                mpack_write_uint(&writer, msg->_msg_uid);
            }
            mpack_finish_map(&writer);

            // finish writing
            if (mpack_writer_destroy(&writer) != mpack_ok) {
                fprintf(stderr, "An error occurred encoding the data!\n");
            }

            // If whole size of packet <= maximum packet size (according to initialization)
            // this msg sending once with the LAST flag set to TRUE
            if (bytes <= (uint16_t)(parser->max_packet_size))
            {
                *packet_size = (uint16_t)bytes;
            }

            msg->state ^= RF62X_MSG_WAIT_CONFIRMATION;
            msg->state |= RF62X_MSG_CONFIRMED;

            // Copy data
            memcpy(&packet_data[0], send_packet, bytes);
            free(send_packet); send_packet = NULL;
            break;
        }else
        {
            *packet_size = 0;
        }

    }

    pthread_mutex_unlock(&parser->input_msg_buff_mutex);
}

void RF62X_parser_get_lost_data_request_packet(RF62X_parser_t *parser, uint8_t *packet_data, uint16_t *packet_size)
{
    (void)parser;
    (void)packet_data;
    (void)packet_size;
}





RF62X_msg_t* RF62X_parser_get_free_output_msg_buffer(RF62X_parser_t *parser)
{

    // Check of initialization of output msg buffer.
    if (parser->output_msg_buffer == NULL)
        return NULL;

    for (int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
    {
        parser->output_msg_index = (parser->output_msg_index + 1) % RF62X_PARSER_OUTPUT_BUFFER_QUEUE;
        RF62X_msg_t* msg = parser->output_msg_buffer[parser->output_msg_index].msg;

        if (msg == NULL)
        {
            return NULL;
        }

        if (msg->state == RF62X_MSG_EMPTY)
        {
            return msg;
        }

        if (msg->state & RF62X_MSG_TIMEOUT)
        {
            msg->_timeout_clb(msg);
            if (msg->state & RF62X_MSG_ANSWERED)
                msg->_free_clb(msg);
            RF62X_cleanup_msg(msg);
            return msg;
        }
    }

    // Если нет свободных сообщений, то взять один из обработаных запросов
    for (int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
    {
        parser->output_msg_index = (parser->output_msg_index + 1) % RF62X_PARSER_OUTPUT_BUFFER_QUEUE;
        RF62X_msg_t* msg = parser->output_msg_buffer[parser->output_msg_index].msg;

        if (msg->state & RF62X_MSG_ANSWERED)
        {
            msg->_free_clb(msg);
            RF62X_cleanup_msg(msg);
            return msg;
        }
    }

    // Если нет обработаных запросов, то скорее всего очередь
    // забита не отвеченными сообщениями.. В этом случае придется использовать
    // последнее из не отвеченных (TODO выбор последнего в очереди)
    for (int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
    {
        parser->output_msg_index = (parser->output_msg_index + 1) % RF62X_PARSER_OUTPUT_BUFFER_QUEUE;
        RF62X_msg_t* msg = parser->output_msg_buffer[parser->output_msg_index].msg;

        if (msg->state & RF62X_MSG_ENCODED)
        {
            RF62X_cleanup_msg(msg);
            return msg;
        }
    }

    return NULL;
}

uint8_t RF62X_parser_add_msg(RF62X_parser_t *parser, RF62X_msg_t *msg)
{
    msg->_device_id = parser->host_device_uid;
    // Check input params.
    if (msg->data_size > parser->max_data_size)
        return FALSE;

    // Check of initialization of output msg buffer.
    if (parser->output_msg_buffer == NULL)
        return FALSE;

    // Change buffer index and change current data ID
    pthread_mutex_lock(&parser->output_msg_buff_mutex);
    RF62X_msg_t* buffer_msg = RF62X_parser_get_free_output_msg_buffer(parser);
    if (buffer_msg == NULL)
    {
        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
        return FALSE;
    }

    // Copy msg
    memcpy(buffer_msg->type, msg->type, strlen(msg->type) + 1);
    memcpy(buffer_msg->cmd_name, msg->cmd_name, strlen(msg->cmd_name) + 1);
    memcpy(buffer_msg->container_type, msg->container_type, strlen(msg->container_type) + 1);

    buffer_msg->check_crc_flag = msg->check_crc_flag;
    buffer_msg->confirmation_flag = msg->confirmation_flag;
    buffer_msg->wait_answ_flag = msg->wait_answ_flag;
    buffer_msg->one_answ_flag = msg->one_answ_flag;

    if (msg->data_size > 0)
    {
        buffer_msg->data = calloc(msg->data_size, sizeof (uint8_t));
        memcpy(buffer_msg->data, msg->data, msg->data_size);
        buffer_msg->data_size = msg->data_size;
    }

    buffer_msg->_answ_clb = msg->_answ_clb;
    buffer_msg->_timeout_clb = msg->_timeout_clb;
    buffer_msg->_free_clb = msg->_free_clb;

    buffer_msg->_msg_uid = msg->_msg_uid;
    buffer_msg->_device_id = msg->_device_id;
    buffer_msg->_uid = msg->_uid;
    buffer_msg->_timeout = msg->_timeout;
    buffer_msg->_sending_time = (uint32_t)(clock() * (1000.0 /CLOCKS_PER_SEC));

    buffer_msg->state = RF62X_MSG_WAIT_ENCODING;

    buffer_msg->result = NULL;
    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
    return TRUE;
}

RF62X_msg_t* RF62X_parser_get_free_input_msg_buffer(RF62X_parser_t *parser)
{
    for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
    {
        parser->input_msg_index = (parser->input_msg_index + 1) % RF62X_PARSER_INPUT_BUFFER_QUEUE;
        RF62X_msg_t* msg = parser->input_msg_buffer[parser->input_msg_index].msg;

        if (msg == NULL)
        {
            return NULL;
        }

        if (msg->state == RF62X_MSG_EMPTY)
        {
            return msg;
        }

        if (msg->state & RF62X_MSG_DECODED &&
                (((msg->state & RF62X_MSG_READ) == TRUE)
                 || ((msg->state & RF62X_MSG_WAIT_READING) == FALSE)))
        {
            RF62X_cleanup_msg(msg);
            return msg;
        }
    }

    // Если нет свободных сообщений, то взять один из входящих запросов, ожидающих прочтение
    for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
    {
        parser->input_msg_index = (parser->input_msg_index + 1) % RF62X_PARSER_INPUT_BUFFER_QUEUE;
        RF62X_msg_t* msg = parser->input_msg_buffer[parser->input_msg_index].msg;

        if (msg->state & RF62X_MSG_WAIT_READING)
        {
            RF62X_cleanup_msg(msg);
            return msg;
        }
    }

    // Если нет входящих запросов, ожидающих прочтение, то скорее всего очередь
    // забита несобранными сообщениями.. В этом случае придется использовать
    // последнее из несобранных (TODO выбор последнего в очереди)
    for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
    {
        parser->input_msg_index = (parser->input_msg_index + 1) % RF62X_PARSER_INPUT_BUFFER_QUEUE;
        RF62X_msg_t* msg = parser->input_msg_buffer[parser->input_msg_index].msg;

        if (msg->state & RF62X_MSG_WAIT_DECODING)
        {
            RF62X_cleanup_msg(msg);
            return msg;
        }
    }
    return NULL;
}

int32_t RF62X_parser_decode_msg(RF62X_parser_t *parser, uint8_t *packet_data, uint16_t packet_size)
{
    int32_t result = RF62X_PARSER_RETURN_STATUS_NO_DATA;

    // Get params
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)packet_data, packet_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        result = RF62X_PARSER_RETURN_STATUS_NO_DATA;
        mpack_tree_destroy(&tree);
        return result;
    }
    mpack_node_t root = mpack_tree_root(&tree);

    // Идентификатор сообщения
    uint32_t msg_uid = 0;
    if (mpack_node_map_contains_cstr(root, "msg_uid"))
    {
        msg_uid = mpack_node_uint(mpack_node_map_cstr(root, "msg_uid"));
        result = RF62X_PARSER_RETURN_STATUS_DATA_CONFIRMATION;
    }

    // Идентификатор устройства
    uint32_t src_device_uid = 0;
    if (mpack_node_map_contains_cstr(root, "src_device_uid"))
    {
        src_device_uid = mpack_node_uint(mpack_node_map_cstr(root, "src_device_uid"));

        if (src_device_uid == parser->host_device_uid)
            return result;
    }


    // Тип команды: rqst - запрос, answ - ответ
    char* type = NULL;
    if (mpack_node_map_contains_cstr(root, "msg"))
    {
        mpack_node_t msg_node = mpack_node_map_cstr(root, "msg");
        if (mpack_node_map_contains_cstr(msg_node, "type"))
        {
            uint32_t type_strlen = (uint32_t)mpack_node_strlen(mpack_node_map_cstr(msg_node, "type")) + 1;
            type = mpack_node_cstr_alloc(mpack_node_map_cstr(msg_node, "type"), type_strlen);
        }
    }

    // Принят запрос
    if (type != NULL && (strcmp(type, "rqst") == 0))
    {
        mpack_node_t msg_node = mpack_node_map_cstr(root, "msg");

        // Логический порт (обработчик команды)
        char* cmd_name = NULL;
        if (mpack_node_map_contains_cstr(msg_node, "name"))
        {
            uint32_t name_strlen = (uint32_t)mpack_node_strlen(mpack_node_map_cstr(msg_node, "name")) + 1;
            cmd_name = mpack_node_cstr_alloc(mpack_node_map_cstr(msg_node, "name"), name_strlen);
        }

        // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
        uint32_t logic_port_uid = 0;
        if (mpack_node_map_contains_cstr(msg_node, "uid"))
        {
            logic_port_uid = mpack_node_uint(mpack_node_map_cstr(msg_node, "uid"));
        }

        // Тип содержимого - chunk, payload
        char* container_type = NULL;
        if (mpack_node_map_contains_cstr(msg_node, "container_type"))
        {
            uint32_t container_type_strlen = (uint32_t)mpack_node_strlen(mpack_node_map_cstr(msg_node, "container_type")) + 1;
            container_type = mpack_node_cstr_alloc(mpack_node_map_cstr(msg_node, "container_type"), container_type_strlen);
        }

        // find input buffer index and change current data ID
        uint8_t is_chousen = FALSE;
        RF62X_msg_t* input_msg = NULL;
        const int lock_rv = pthread_mutex_lock(&parser->input_msg_buff_mutex);
        if (lock_rv)
        {
            error_pthread_mutex_lock(lock_rv);
            return FALSE;
        }
        // Поиск среди имеющихся уже сообщений с тем же _uid
        for (uint16_t i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
        {
            if (parser->input_msg_buffer[i].msg->_uid == logic_port_uid &&
                    strcmp(parser->input_msg_buffer[i].msg->cmd_name, cmd_name) == 0)
            {
                parser->input_msg_index = i;
                input_msg = parser->input_msg_buffer[i].msg;
                is_chousen = TRUE;
                break;
            }
        }

        // Если ранее не получено было это сообщение, то поиск первого свободного
        if (is_chousen == FALSE)
        {
            input_msg = RF62X_parser_get_free_input_msg_buffer(parser);
        }

        // TODO: Если все заняты, то использовать последнее в очереди сообщение в буфере
        if (input_msg == NULL)
        {
            pthread_mutex_unlock(&parser->input_msg_buff_mutex);
            return RF62X_PARSER_RETURN_STATUS_NO_FREE_BUFFER;
        }

        if (mpack_node_map_contains_cstr(msg_node, "chunk"))
        {
            mpack_node_t chunk = mpack_node_map_cstr(msg_node, "chunk");

            if (msg_uid != 0 && input_msg->_msg_uid == msg_uid)
            {
                free(type); type = NULL;
                free(cmd_name); cmd_name = NULL;
                free(container_type); container_type = NULL;
                mpack_tree_destroy(&tree);
                pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                return result;
            }


            if (input_msg->state == RF62X_MSG_EMPTY)
            {
                // Init new input data atributes
                input_msg->_msg_uid = msg_uid;
                if (input_msg->_msg_uid != 0)
                    input_msg->confirmation_flag = TRUE;
                input_msg->_uid = logic_port_uid;
                input_msg->_device_id = src_device_uid;
                input_msg->state = RF62X_MSG_WAIT_DECODING;

                memcpy(input_msg->cmd_name, (char*)cmd_name, strlen(cmd_name) + 1);

                // Полный размер
                uint32_t chain_size = 0;
                if (mpack_node_map_contains_cstr(chunk, "chain_size"))
                {
                    chain_size = mpack_node_uint(mpack_node_map_cstr(chunk, "chain_size"));
                    // Allocate memmory for data
                    input_msg->data = calloc(chain_size, sizeof (uint8_t));
                    // Reset mask value
                    parser->input_msg_buffer[parser->input_msg_index].mask =
                            calloc(chain_size, sizeof (uint8_t));
                    memset(parser->input_msg_buffer[parser->input_msg_index].mask, 0, chain_size);
                }

                input_msg->data_size = chain_size;
                parser->input_msg_buffer[parser->input_msg_index].received_size = 0;
                parser->input_msg_buffer[parser->input_msg_index].data_pos = 0;

                // crc
                uint32_t chain_crc16 = 0;
                if (mpack_node_map_contains_cstr(chunk, "chain_crc16"))
                {
                    chain_crc16 = mpack_node_uint(mpack_node_map_cstr(chunk, "chain_crc16"));
                    input_msg->check_crc_flag = TRUE;
                }
            }

            // offset
            uint32_t offset = 0;
            if (mpack_node_map_contains_cstr(chunk, "offset"))
            {
                offset = mpack_node_uint(mpack_node_map_cstr(chunk, "offset"));
            }

            // last flag
            uint8_t is_last = FALSE;
            if (mpack_node_map_contains_cstr(chunk, "last"))
            {
                is_last = mpack_node_bool(mpack_node_map_cstr(chunk, "last"));
            }

            // Бинарные данные
            uint32_t data_size = 0;
            char* data = NULL;
            if (mpack_node_map_contains_cstr(chunk, "data"))
            {
                data_size = mpack_node_data_len(mpack_node_map_cstr(chunk, "data"));
                data = mpack_node_data_alloc(mpack_node_map_cstr(chunk, "data"), data_size);
            }

            // Copy data if it is not empty DATA packet.
            if (data_size > 0 && parser->input_msg_buffer[parser->input_msg_index].mask[offset] != 1)
            {
                memcpy(&input_msg->data[offset], data, data_size);
                // Update data position if it is next data in data buffer (not previous data in data buffers)
                parser->input_msg_buffer[parser->input_msg_index].data_pos = offset + data_size;
                // Update data counter. If this potion of data wasn't recieved before we update data counter.
                parser->input_msg_buffer[parser->input_msg_index].received_size += data_size;
                parser->input_msg_buffer[parser->input_msg_index].mask[offset] = 1;
            }

            // TODO: Check lost data. Check if there is a gap between the last
            if (is_last)
            {
                if (parser->input_msg_buffer[parser->input_msg_index].received_size ==
                        input_msg->data_size)
                {
                    // Copy data to ready input data buffer
                    // Init input data buffer
//                    if (parser->input_data_buff == NULL)
//                        parser->input_data_buff =
//                                calloc ((*input_msg->msg)->data_size, sizeof (uint8_t));

                    // Check input data ID. If data was copied befor then won't copy egain.
                    for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
                    {
                        if ((parser->input_msg_buffer[i].msg->state & RF62X_MSG_WAIT_READING) &&
                                parser->input_msg_buffer[i].msg->_uid == input_msg->_uid)
                        {
                            free(type); type = NULL;
                            free(cmd_name); cmd_name = NULL;
                            free(container_type); container_type = NULL;
                            free(data); data = NULL;
                            mpack_tree_destroy(&tree);
                            pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                            return result;
                        }
                    }

                    // Copy data to input buffer and copy data atributes.
//                    pthread_mutex_lock(&parser->input_data_buff_mutex);
//                    memcpy(parser->input_data_buff, (*input_msg->msg)->data, (*input_msg->msg)->data_size);
//                    parser->input_data_buff_size = (*input_msg->msg)->data_size;
//                    parser->input_data_id = (*input_msg->msg)->_uid;
//                    strcpy(parser->input_data_cmd_name, cmd_name);
//                    pthread_mutex_unlock(&parser->input_data_buff_mutex);

                    input_msg->state |= RF62X_MSG_WAIT_READING;
                    input_msg->state ^= RF62X_MSG_WAIT_DECODING;
                    input_msg->state |= RF62X_MSG_DECODED;

                    if (input_msg->confirmation_flag && msg_uid != 0)
                    {
                        input_msg->state |= RF62X_MSG_WAIT_CONFIRMATION;
                        input_msg->_msg_uid = msg_uid;
                        result = RF62X_PARSER_RETURN_STATUS_DATA_CONFIRMATION;
                    }else
                    {
                        result = RF62X_PARSER_RETURN_STATUS_DATA_READY;
                    }

//                    memset(parser->input_msg_buffer[parser->input_msg_index].mask, 0, input_msg->data_size);
                    free(parser->input_msg_buffer[parser->input_msg_index].mask);
                    pthread_mutex_unlock(&parser->input_msg_buff_mutex);

                    free(type); type = NULL;
                    free(cmd_name); cmd_name = NULL;
                    free(container_type); container_type = NULL;
                    free(data); data = NULL;
                    mpack_tree_destroy(&tree);

                    // Send notification about new data
                    pthread_mutex_lock(&parser->input_data_cond_var_mutex);
                    if (!parser->input_data_cond_var_flag)
                        pthread_cond_signal(&parser->input_data_cond_var);
                    parser->input_data_cond_var_flag = TRUE;
                    pthread_mutex_unlock(&parser->input_data_cond_var_mutex);
                    return result;
                }
                else
                {
                    free(type); type = NULL;
                    free(cmd_name); cmd_name = NULL;
                    free(container_type); container_type = NULL;
                    free(data); data = NULL;
                    mpack_tree_destroy(&tree);
                    pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_LOST_DATA_DETECTED;
                }
            }
            else
            {
                free(type); type = NULL;
                free(cmd_name); cmd_name = NULL;
                free(container_type); container_type = NULL;
                free(data); data = NULL;
                mpack_tree_destroy(&tree);
                if (input_msg->confirmation_flag && msg_uid != 0)
                {
                    input_msg->state |= RF62X_MSG_WAIT_CONFIRMATION;
                    input_msg->_msg_uid = msg_uid;
                    pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA_CONFIRMATION;
                }else
                {
                    pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                    return result;
                }
            }

        }

        pthread_mutex_unlock(&parser->input_msg_buff_mutex);
    }
    else if (type != NULL && (strcmp(type, "answ") == 0))
    {
        mpack_node_t msg_node = mpack_node_map_cstr(root, "msg");

        // Логический порт (обработчик команды)
        char* cmd_name = NULL;
        if (mpack_node_map_contains_cstr(msg_node, "name"))
        {
            uint32_t name_strlen = (uint32_t)mpack_node_strlen(mpack_node_map_cstr(msg_node, "name")) + 1;
            cmd_name = mpack_node_cstr_alloc(mpack_node_map_cstr(msg_node, "name"), name_strlen);
        }

        // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
        uint32_t logic_port_uid = 0;
        if (mpack_node_map_contains_cstr(msg_node, "uid"))
        {
            logic_port_uid = mpack_node_uint(mpack_node_map_cstr(msg_node, "uid"));
        }

        // Тип содержимого - chunk, payload
        char* container_type = NULL;
        if (mpack_node_map_contains_cstr(msg_node, "container_type"))
        {
            uint32_t container_type_strlen = (uint32_t)mpack_node_strlen(mpack_node_map_cstr(msg_node, "container_type")) + 1;
            container_type = mpack_node_cstr_alloc(mpack_node_map_cstr(msg_node, "container_type"), container_type_strlen);
        }

        pthread_mutex_lock(&parser->output_msg_buff_mutex);
        pthread_mutex_lock(&parser->input_msg_buff_mutex);
        // Проверить ожидает ли какой-нибудь запрос ответ
        for (int ii = 0; ii < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; ii++)
        {
            RF62X_msg_t* output_msg = parser->output_msg_buffer[ii].msg;
            RF62X_msg_t* input_msg = NULL;
            if ((output_msg->_uid == logic_port_uid) &&
                    ((output_msg->state & RF62X_MSG_WAIT_ANSW) ||
                        (output_msg->state & RF62X_MSG_WAIT_ENCODING)))
            {
                // find input buffer index and change current data ID
                uint8_t is_chousen = FALSE;
                // Поиск среди имеющихся уже сообщений с тем же _uid
                for (uint16_t i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
                {
                    if (parser->input_msg_buffer[i].msg->_uid == logic_port_uid &&
                            parser->input_msg_buffer[i].msg->_device_id == src_device_uid &&
                            strcmp(parser->input_msg_buffer[i].msg->cmd_name, cmd_name) == 0 &&
                            parser->input_msg_buffer[i].msg->state & RF62X_MSG_WAIT_DECODING)
                    {
                        parser->input_msg_index = i;
                        input_msg = parser->input_msg_buffer[i].msg;
                        is_chousen = TRUE;
                        break;
                    }
                }

                // Если ранее не получено было это сообщение, то поиск первого свободного
                if (is_chousen == FALSE)
                {
                    input_msg = RF62X_parser_get_free_input_msg_buffer(parser);
                }

                // TODO: Если все заняты, то использовать последнее в очереди сообщение в буфере
                if (input_msg == NULL)
                {
                    pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_NO_FREE_BUFFER;
                }

                if (mpack_node_map_contains_cstr(msg_node, "chunk"))
                {
                    mpack_node_t chunk = mpack_node_map_cstr(msg_node, "chunk");

                    if (msg_uid != 0 && input_msg->_msg_uid == msg_uid)
                    {
                        free(type); type = NULL;
                        free(cmd_name); cmd_name = NULL;
                        free(container_type); container_type = NULL;
                        mpack_tree_destroy(&tree);
                        pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return result;
                    }

                    if (input_msg->state == RF62X_MSG_EMPTY)
                    {
                        // Init new input data atributes
                        input_msg->_msg_uid = msg_uid;
                        if (input_msg->_msg_uid != 0)
                            input_msg->confirmation_flag = TRUE;
                        input_msg->_uid = logic_port_uid;
                        input_msg->_device_id = src_device_uid;
                        input_msg->state = RF62X_MSG_WAIT_DECODING;

                        memcpy(input_msg->cmd_name, (char*)cmd_name, strlen(cmd_name) + 1);

                        // Полный размер
                        uint32_t chain_size = 0;
                        if (mpack_node_map_contains_cstr(chunk, "chain_size"))
                        {
                            chain_size = mpack_node_uint(mpack_node_map_cstr(chunk, "chain_size"));
                            // Allocate memmory for data
                            input_msg->data = calloc(chain_size, sizeof (uint8_t));
                            // Reset mask value
                            parser->input_msg_buffer[parser->input_msg_index].mask =
                                    calloc(chain_size, sizeof (uint8_t));
                            memset(parser->input_msg_buffer[parser->input_msg_index].mask, 0, chain_size);
                        }

                        input_msg->data_size = chain_size;
                        parser->input_msg_buffer[parser->input_msg_index].received_size = 0;
                        parser->input_msg_buffer[parser->input_msg_index].data_pos = 0;

                        // crc
                        uint32_t chain_crc16 = 0;
                        if (mpack_node_map_contains_cstr(chunk, "chain_crc16"))
                        {
                            chain_crc16 = mpack_node_uint(mpack_node_map_cstr(chunk, "chain_crc16"));
                        }
                    }

                    // offset
                    uint32_t offset = 0;
                    if (mpack_node_map_contains_cstr(chunk, "offset"))
                    {
                        offset = mpack_node_uint(mpack_node_map_cstr(chunk, "offset"));
                    }

                    // last flag
                    uint8_t is_last = FALSE;
                    if (mpack_node_map_contains_cstr(chunk, "last"))
                    {
                        is_last = mpack_node_bool(mpack_node_map_cstr(chunk, "last"));
                    }

                    // Бинарные данные
                    uint32_t data_size = 0;
                    char* data = NULL;
                    if (mpack_node_map_contains_cstr(chunk, "data"))
                    {
                        data_size = mpack_node_data_len(mpack_node_map_cstr(chunk, "data"));
                        data = mpack_node_data_alloc(mpack_node_map_cstr(chunk, "data"), data_size);
                    }

                    // Copy data if it is not empty DATA packet.
                    if (data_size > 0 && parser->input_msg_buffer[parser->input_msg_index].mask[offset] != 1)
                    {
                        memcpy(&input_msg->data[offset], data, data_size);
                        // Update data position if it is next data in data buffer (not previous data in data buffers)
                        parser->input_msg_buffer[parser->input_msg_index].data_pos = offset + data_size;
                        // Update data counter. If this potion of data wasn't recieved before we update data counter.
                        parser->input_msg_buffer[parser->input_msg_index].received_size += data_size;
                        parser->input_msg_buffer[parser->input_msg_index].mask[offset] = 1;
                    }

                    // TODO: Check lost data. Check if there is a gap between the last
                    if (is_last)
                    {
                        if (parser->input_msg_buffer[parser->input_msg_index].received_size ==
                                input_msg->data_size)
                        {
                            // Check input data ID. If data was copied befor then won't copy egain.
                            for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
                            {
                                if ((parser->input_msg_buffer[i].msg->state & RF62X_MSG_WAIT_READING) &&
                                        parser->input_msg_buffer[i].msg->_uid == input_msg->_uid)
                                {
                                    free(type); type = NULL;
                                    free(cmd_name); cmd_name = NULL;
                                    free(container_type); container_type = NULL;
                                    free(data); data = NULL;
                                    mpack_tree_destroy(&tree);
                                    pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                                    return result;
                                }
                            }

                            // Copy data to input buffer and copy data atributes.
                            if (output_msg->state & RF62X_MSG_WAIT_ANSW)
                                output_msg->_answ_clb(
                                            input_msg->data, input_msg->data_size,
                                            src_device_uid, output_msg);
                            if (output_msg->one_answ_flag)
                            {
                                output_msg->state ^= RF62X_MSG_WAIT_ANSW;
                                output_msg->state |= RF62X_MSG_ANSWERED;
                            }

                            free(type); type = NULL;
                            free(cmd_name); cmd_name = NULL;
                            free(container_type); container_type = NULL;
                            free(data); data = NULL;
                            mpack_tree_destroy(&tree);
                            input_msg->state ^= RF62X_MSG_WAIT_DECODING;
                            input_msg->state |= RF62X_MSG_DECODED;
                            free(parser->input_msg_buffer[parser->input_msg_index].mask);
                            if (output_msg->confirmation_flag && msg_uid != 0)
                            {
                                input_msg->state |= RF62X_MSG_WAIT_CONFIRMATION;
                                input_msg->_msg_uid = msg_uid;
                                pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                                pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                                return RF62X_PARSER_RETURN_STATUS_DATA_CONFIRMATION;
                            }else
                            {
                                pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                                pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                                return RF62X_PARSER_RETURN_STATUS_DATA_READY;
                            }
                        }
                        else
                        {
                            free(type); type = NULL;
                            free(cmd_name); cmd_name = NULL;
                            free(container_type); container_type = NULL;
                            free(data); data = NULL;
                            mpack_tree_destroy(&tree);
                            pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                            pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                            return RF62X_PARSER_RETURN_STATUS_LOST_DATA_DETECTED;
                        }
                    }
                    else
                    {
                        free(type); type = NULL;
                        free(cmd_name); cmd_name = NULL;
                        free(container_type); container_type = NULL;
                        free(data); data = NULL;
                        mpack_tree_destroy(&tree);
                        if (output_msg->confirmation_flag && msg_uid != 0)
                        {
                            input_msg->state |= RF62X_MSG_WAIT_CONFIRMATION;
                            input_msg->_msg_uid = msg_uid;
                            pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                            pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                            return RF62X_PARSER_RETURN_STATUS_DATA_CONFIRMATION;
                        }else
                        {
                            pthread_mutex_unlock(&parser->input_msg_buff_mutex);
                            pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                            return result;
                        }
                    }
                }
            }
        }

        free(cmd_name);
        free(container_type);

        pthread_mutex_unlock(&parser->input_msg_buff_mutex);
        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
    }
    else if (mpack_node_map_contains_cstr(root, "ack_uid"))
    {
        // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
        uint32_t logic_port_uid = mpack_node_uint(mpack_node_map_cstr(root, "ack_uid"));

        const int lock_rv = pthread_mutex_lock(&parser->output_msg_buff_mutex);
        if (lock_rv)
        {
            error_pthread_mutex_lock(lock_rv);
            return FALSE;
        }
        // Проверить ожидает ли какой-нибудь запрос ответ
        for (int ii = 0; ii < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; ii++)
        {
            RF62X_msg_t* msg = parser->output_msg_buffer[ii].msg;

            if ((msg->_msg_uid == logic_port_uid) &&
                    (msg->state & RF62X_MSG_WAIT_CONFIRMATION))
            {
                msg->state ^= RF62X_MSG_WAIT_CONFIRMATION;
                msg->state |= RF62X_MSG_CONFIRMED;

                // Send notification about new data
                pthread_mutex_lock(&parser->input_wait_confirm_var_mutex);
                parser->input_wait_confirm_cond_var_flag = TRUE;
                pthread_cond_signal(&parser->input_wait_confirm_cond_var);
                pthread_mutex_unlock(&parser->input_wait_confirm_var_mutex);

                free(type); type = NULL;
                mpack_tree_destroy(&tree);
                pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                return RF62X_PARSER_RETURN_STATUS_DATA_READY;
            }
        }
        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
    }

    free(type); type = NULL;
    mpack_tree_destroy(&tree);
    // Return DATA flag.
    return RF62X_PARSER_RETURN_STATUS_DATA;
}

uint16_t crc16(const uint8_t *data, uint32_t len)
{
    uint16_t crc = 0;
    uint16_t* data16 = (uint16_t*)data;

    while(len > 1)
    {
        crc += 44111 * *data16++;
        len -= sizeof(uint16_t);
    }
    if (len > 0) crc += *(uint8_t*)data16;
    crc = crc ^ (crc >> 8);
    return crc;
}
int test_count = 1;
int32_t RF62X_parser_encode_msg(RF62X_parser_t *parser, uint8_t *packet_data, uint16_t *packet_size)
{
    // Check output msg initialization.
    if (parser->output_msg_buffer == NULL)
        return RF62X_PARSER_RETURN_STATUS_NO_DATA;

    const int lock_rv = pthread_mutex_lock(&parser->output_msg_buff_mutex);
    if (lock_rv)
    {
        error_pthread_mutex_lock(lock_rv);
        return FALSE;
    }

    RF62X_msg_t* msg = parser->output_msg_buffer[parser->output_msg_index].msg;
    // Check data confirmation.
    if (msg->state & RF62X_MSG_WAIT_ENCODING)
    {
        // If this is the first message in the chain, then we need to add
        // all the keys to the message
        if (parser->output_msg_buffer[parser->output_msg_index].data_pos == 0)
        {
            // If there is still data to include in the package DATA then we form a data package.
            if (parser->output_msg_buffer[parser->output_msg_index].data_pos <=
                    msg->data_size)
            {
                // The size of the data to be included in the package is equal to data_size,
                // since the data_pos = 0;
                int32_t playload_size = msg->data_size;

                // Create FULL DATA packet for measurement SIZE of data packet
                mpack_writer_t writer;
                char* send_packet = NULL;
                size_t bytes = 0;				///< Number of msg bytes.
                mpack_writer_init_growable(&writer, &send_packet, &bytes);

                // write the example on the msgpack homepage
                mpack_start_map(&writer, msg->confirmation_flag?3:2);
                {
                    // Идентификатор сообщения для подтверждения
                    if (msg->confirmation_flag)
                    {
                        mpack_write_cstr(&writer, "msg_uid");
                        msg->_msg_uid = test_count++;//rand() % (UINT64_MAX-1) + 1;
                        mpack_write_uint(&writer, msg->_msg_uid);
                    }

                    // Идентификатор устройства, отправившего сообщения
                    mpack_write_cstr(&writer, "src_device_uid");
                    mpack_write_uint(&writer, parser->host_device_uid);


                    // Сообщение
                    mpack_write_cstr(&writer, "msg"); mpack_start_map(&writer, strcmp(msg->container_type, "blob") != 0? 5 : 4);
                    {
                        // Тип команды: rqst - запрос, answ - ответ
                        mpack_write_cstr(&writer, "type");
                        mpack_write_cstr(&writer, msg->type);

                        // Логический порт (обработчик команды)
                        mpack_write_cstr(&writer, "name");
                        mpack_write_cstr(&writer, msg->cmd_name);

                        // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
                        mpack_write_cstr(&writer, "uid");
                        mpack_write_uint(&writer, msg->_uid);

                        // Если присутствует - указывает, каким протоколом упакованы данные в цепочке, если нет - сырые данные
                        if (strcmp(msg->container_type, "blob") != 0)
                        {
                            mpack_write_cstr(&writer, "container_type");
                            mpack_write_cstr(&writer, msg->container_type);
                        }

                        mpack_write_cstr(&writer, "chunk"); mpack_start_map(&writer, msg->check_crc_flag?5:4);
                        {
                            // Полный размер
                            mpack_write_cstr(&writer, "chain_size");
                            mpack_write_uint(&writer, msg->data_size);

                            // crc-16
                            if(msg->check_crc_flag)
                            {
                                mpack_write_cstr(&writer, "chain_crc16");
                                mpack_write_uint(&writer, crc16((uint8_t*)msg->data, msg->data_size));
                            }

                            // Смещение фрагмента данных в цепочке
                            mpack_write_cstr(&writer, "offset");
                            mpack_write_uint(&writer, parser->output_msg_buffer[parser->output_msg_index].data_pos);

                            // Флаг последнего фрагмента
                            mpack_write_cstr(&writer, "last");
                            mpack_write_bool(&writer, TRUE);

                            // Бинарные данные
                            mpack_write_cstr(&writer, "data");
                            mpack_write_bin(&writer, (char*)&msg->data[parser->output_msg_buffer[parser->output_msg_index].data_pos], playload_size);

                        }
                        mpack_finish_map(&writer);
                    }
                    mpack_finish_map(&writer);
                }
                mpack_finish_map(&writer);

                // finish writing
                if (mpack_writer_destroy(&writer) != mpack_ok) {
                    fprintf(stderr, "An error occurred encoding the data!\n");
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return FALSE;
                }

                // If whole size of packet <= maximum packet size (according to initialization)
                // this msg sending once with the LAST flag set to TRUE
                if (bytes <= (uint16_t)(parser->max_packet_size))
                {
                    *packet_size = (uint16_t)bytes;
                }
                // Otherwise, the msg needs to be re-encoded with the LAST flag set to FALSE
                // and sent on the pieces
                else if (bytes > (uint16_t)(parser->max_packet_size))
                {
                    free(send_packet); send_packet = NULL;

                    uint32_t header_size = (uint32_t)bytes - msg->data_size;
                    // secure reserve on maximum packet size is 10%
                    playload_size = (uint32_t)(parser->max_packet_size * 0.90) - header_size;

                    if (playload_size < 0)
                    {
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return FALSE;
                    }

                    // Create first CHAIN DATA packet
                    bytes = 0;				///< Number of msg bytes.
                    mpack_writer_init_growable(&writer, &send_packet, &bytes);

                    // write the example on the msgpack homepage
                    mpack_start_map(&writer, msg->confirmation_flag?3:2);
                    {
                        // Идентификатор сообщения для подтверждения
                        if (msg->confirmation_flag)
                        {
                            mpack_write_cstr(&writer, "msg_uid");
                            mpack_write_uint(&writer, msg->_msg_uid);
                        }

                        // Идентификатор устройства, отправившего сообщения
                        mpack_write_cstr(&writer, "src_device_uid");
                        mpack_write_uint(&writer, parser->host_device_uid);

                        // Сообщение
                        mpack_write_cstr(&writer, "msg"); mpack_start_map(&writer, strcmp(msg->container_type, "blob") != 0? 5 : 4);
                        {
                            // Тип команды: rqst - запрос, answ - ответ
                            mpack_write_cstr(&writer, "type");
                            mpack_write_cstr(&writer, msg->type);

                            // Логический порт (обработчик команды)
                            mpack_write_cstr(&writer, "name");
                            mpack_write_cstr(&writer, msg->cmd_name);

                            // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
                            mpack_write_cstr(&writer, "uid");
                            mpack_write_uint(&writer, msg->_uid);

                            // Если присутствует - указывает, каким протоколом упакованы данные в цепочке, если нет - сырые данные
                            if (strcmp(msg->container_type, "blob") != 0)
                            {
                                mpack_write_cstr(&writer, "container_type");
                                mpack_write_cstr(&writer, msg->container_type);
                            }

                            mpack_write_cstr(&writer, "chunk"); mpack_start_map(&writer, msg->check_crc_flag?5:4);
                            {
                                // Полный размер
                                mpack_write_cstr(&writer, "chain_size");
                                mpack_write_uint(&writer, msg->data_size);

                                // crc-16
                                if(msg->check_crc_flag)
                                {
                                    mpack_write_cstr(&writer, "chain_crc16");
                                    mpack_write_uint(&writer, crc16((uint8_t*)msg->data, msg->data_size));
                                }

                                // Смещение фрагмента данных в цепочке
                                mpack_write_cstr(&writer, "offset");
                                mpack_write_uint(&writer, parser->output_msg_buffer[parser->output_msg_index].data_pos);

                                // Флаг последнего фрагмента
                                mpack_write_cstr(&writer, "last");
                                mpack_write_bool(&writer, FALSE);

                                // Бинарные данные
                                mpack_write_cstr(&writer, "data");
                                mpack_write_bin(&writer, (char*)&msg->data[parser->output_msg_buffer[parser->output_msg_index].data_pos], playload_size);

                            }
                            mpack_finish_map(&writer);
                        }
                        mpack_finish_map(&writer);
                    }
                    mpack_finish_map(&writer);

                    // finish writing
                    if (mpack_writer_destroy(&writer) != mpack_ok) {
                        fprintf(stderr, "An error occurred encoding the data!\n");
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return FALSE;
                    }

                    *packet_size = (uint16_t)bytes;

                }

                // Copy data
                memcpy(&packet_data[0], send_packet, bytes);
                free(send_packet); send_packet = NULL;

                // Increase data position
                parser->output_msg_buffer[parser->output_msg_index].data_pos += playload_size;

                // Return DATA packet flag
                if (msg->confirmation_flag)
                    msg->state |= RF62X_MSG_WAIT_CONFIRMATION;

                // Если сообщение полностью закодировано, то добавить соответствующие флаги
                if (parser->output_msg_buffer[parser->output_msg_index].data_pos >=
                        (uint32_t)(msg->data_size))
                {
                    msg->state = RF62X_MSG_ENCODED;
                    if (msg->wait_answ_flag)
                        msg->state |= RF62X_MSG_WAIT_ANSW;
                    if (msg->confirmation_flag)
                        msg->state |= RF62X_MSG_WAIT_CONFIRMATION;

                    parser->output_msg_buffer[parser->output_msg_index].data_pos = 0;

                }

                // Таймер готовности сообщения к отправке
                msg->_sending_time = (uint32_t)(clock() * (1000.0 /CLOCKS_PER_SEC));
                // TODO надо ли возвращать именно RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION
                if (msg->confirmation_flag)
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION;
                }
                else if (msg->state & RF62X_MSG_ENCODED)
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA_READY;
                }else
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA;
                }
            }
        }
        // Otherwise, some optional fields may not be inserted in
        // the message, such as chain_size and chain_crc16
        else
        {
            // If there is still data to include in the package DATA then we form a data package.
            if (parser->output_msg_buffer[parser->output_msg_index].data_pos <
                    msg->data_size)
            {

                if (msg->state & RF62X_MSG_WAIT_CONFIRMATION)
                {
                    if ((clock() * (1000.0 /CLOCKS_PER_SEC) - msg->_sending_time) <
                            msg->_timeout)
                    {
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION;
                    }else
                    {
                        // TODO Нужно ли только в одном месте чистить сообщения
//                        msg->_timeout_clb(parser->output_msg_buffer[parser->output_msg_index].msg);
//                        msg->state |= RF62X_MSG_TIMEOUT;
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT;
                    }
                }

                // TODO нужно ли контролировать время отправки данных
//                if (parser->output_msg_buffer[parser->output_msg_index].msg->_timeout > 0)
//                {
//                    if ((clock() - parser->output_msg_buffer[parser->output_msg_index].msg->_sending_time) >
//                            parser->output_msg_buffer[parser->output_msg_index].msg->_timeout)
//                    {
//                        parser->output_msg_buffer[parser->output_msg_index].msg->_timeout_clb(
//                                    parser->output_msg_buffer[parser->output_msg_index].msg);
//                        parser->output_msg_buffer[parser->output_msg_index].msg->state |= RF62X_MSG_TIMEOUT;
//                        return RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT;
//                    }
//                }

//                parser->output_msg_buffer[parser->output_msg_index].msg->_sending_time = clock();

                // Calculate size of data to include in packet.
                uint32_t playload_size = msg->data_size -
                        parser->output_msg_buffer[parser->output_msg_index].data_pos;

                // Create SHORT DATA packet for measurement SIZE of data packet
                mpack_writer_t writer;
                char* send_packet = NULL;
                size_t bytes = 0;				///< Number of msg bytes.
                mpack_writer_init_growable(&writer, &send_packet, &bytes);

                // write the example on the msgpack homepage
                mpack_start_map(&writer, msg->confirmation_flag?3:2);
                {
                    // Идентификатор сообщения для подтверждения
                    if (msg->confirmation_flag)
                    {
                        mpack_write_cstr(&writer, "msg_uid");
                        msg->_msg_uid = test_count++;
                        mpack_write_uint(&writer, msg->_msg_uid);
                    }

                    // Идентификатор устройства, отправившего сообщения
                    mpack_write_cstr(&writer, "src_device_uid");
                    mpack_write_uint(&writer, parser->host_device_uid);

                    // Сообщение
                    mpack_write_cstr(&writer, "msg"); mpack_start_map(&writer, strcmp(msg->container_type, "blob") != 0? 5 : 4);
                    {
                        // Тип команды: rqst - запрос, answ - ответ
                        mpack_write_cstr(&writer, "type");
                        mpack_write_cstr(&writer, msg->type);

                        // Логический порт (обработчик команды)
                        mpack_write_cstr(&writer, "name");
                        mpack_write_cstr(&writer, msg->cmd_name);

                        // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
                        mpack_write_cstr(&writer, "uid");
                        mpack_write_uint(&writer, msg->_uid);

                        // Если присутствует - указывает, каким протоколом упакованы данные в цепочке, если нет - сырые данные
                        if (strcmp(msg->container_type, "blob") != 0)
                        {
                            mpack_write_cstr(&writer, "container_type");
                            mpack_write_cstr(&writer, msg->container_type);
                        }

                        mpack_write_cstr(&writer, "chunk"); mpack_start_map(&writer, 3);
                        {
                            // Смещение фрагмента данных в цепочке
                            mpack_write_cstr(&writer, "offset");
                            mpack_write_uint(&writer, parser->output_msg_buffer[parser->output_msg_index].data_pos);

                            // Флаг последнего фрагмента
                            mpack_write_cstr(&writer, "last");
                            mpack_write_bool(&writer, TRUE);

                            // Бинарные данные
                            mpack_write_cstr(&writer, "data");
                            mpack_write_bin(&writer, (char*)&msg->data[parser->output_msg_buffer[parser->output_msg_index].data_pos], playload_size);

                        }
                        mpack_finish_map(&writer);
                    }
                    mpack_finish_map(&writer);
                }
                mpack_finish_map(&writer);

                // finish writing
                if (mpack_writer_destroy(&writer) != mpack_ok) {
                    fprintf(stderr, "An error occurred encoding the data!\n");
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return FALSE;
                }

                // If whole size of packet <= maximum packet size (according to initialization)
                // this msg sending once with the LAST flag set to TRUE
                if (bytes <= (uint16_t)(parser->max_packet_size))
                {
                   *packet_size = (uint16_t)bytes;
                }
                // Otherwise, the msg needs to be re-encoded with the LAST flag set to FALSE
                // and sent on the pieces
                else if (bytes > (uint16_t)(parser->max_packet_size))
                {
                    free(send_packet); send_packet = NULL;

                    uint32_t header_size = (uint32_t)bytes - (msg->data_size - parser->output_msg_buffer[parser->output_msg_index].data_pos);
                    // secure reserve on maximum packet size is 10%
                    playload_size = (uint32_t)(parser->max_packet_size * 0.90) - header_size;

                    if (playload_size < 0)
                    {
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return FALSE;
                    }

                    // Create CHAIN DATA packet
                    bytes = 0;				///< Number of msg bytes.
                    mpack_writer_init_growable(&writer, &send_packet, &bytes);

                    // write the example on the msgpack homepage
                    mpack_start_map(&writer, msg->confirmation_flag?3:2);
                    {
                        // Идентификатор сообщения для подтверждения
                        if (msg->confirmation_flag)
                        {
                            mpack_write_cstr(&writer, "msg_uid");
                            //msg->_msg_uid = test_count++;//rand() % (UINT64_MAX-1) + 1;
                            mpack_write_uint(&writer, msg->_msg_uid);
                        }

                        // Идентификатор устройства, отправившего сообщения
                        mpack_write_cstr(&writer, "src_device_uid");
                        mpack_write_uint(&writer, parser->host_device_uid);


                        // Сообщение
                        mpack_write_cstr(&writer, "msg"); mpack_start_map(&writer, strcmp(msg->container_type, "blob") != 0? 5 : 4);
                        {
                            // Тип команды: rqst - запрос, answ - ответ
                            mpack_write_cstr(&writer, "type");
                            mpack_write_cstr(&writer, msg->type);

                            // Логический порт (обработчик команды)
                            mpack_write_cstr(&writer, "name");
                            mpack_write_cstr(&writer, msg->cmd_name);

                            // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
                            mpack_write_cstr(&writer, "uid");
                            mpack_write_uint(&writer, msg->_uid);

                            // Если присутствует - указывает, каким протоколом упакованы данные в цепочке, если нет - сырые данные
                            if (strcmp(msg->container_type, "blob") != 0)
                            {
                                mpack_write_cstr(&writer, "container_type");
                                mpack_write_cstr(&writer, msg->container_type);
                            }

                            mpack_write_cstr(&writer, "chunk"); mpack_start_map(&writer, 3);
                            {
                                // Смещение фрагмента данных в цепочке
                                mpack_write_cstr(&writer, "offset");
                                mpack_write_uint(&writer, parser->output_msg_buffer[parser->output_msg_index].data_pos);

                                // Флаг последнего фрагмента
                                mpack_write_cstr(&writer, "last");
                                mpack_write_bool(&writer, FALSE);

                                // Бинарные данные
                                mpack_write_cstr(&writer, "data");
                                mpack_write_bin(&writer, (char*)&msg->data[parser->output_msg_buffer[parser->output_msg_index].data_pos], playload_size);

                            }
                            mpack_finish_map(&writer);
                        }
                        mpack_finish_map(&writer);
                    }
                    mpack_finish_map(&writer);

                    // finish writing
                    if (mpack_writer_destroy(&writer) != mpack_ok) {
                        fprintf(stderr, "An error occurred encoding the data!\n");
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return FALSE;
                    }

                    *packet_size = (uint16_t)bytes;
                }

                // Copy data
                memcpy(&packet_data[0], send_packet, bytes);
                free(send_packet); send_packet = NULL;

                // Increase data position
                parser->output_msg_buffer[parser->output_msg_index].data_pos += playload_size;

                // Если сообщение полностью закодировано, то добавить соответствующие флаги
                if (parser->output_msg_buffer[parser->output_msg_index].data_pos >=
                        (uint32_t)(msg->data_size))
                {
                    msg->state = RF62X_MSG_ENCODED;
                    if (msg->wait_answ_flag)
                        msg->state |= RF62X_MSG_WAIT_ANSW;

                    parser->output_msg_buffer[parser->output_msg_index].data_pos = 0;

                }

                // Return DATA packet flag
                if (msg->confirmation_flag)
                    msg->state |= RF62X_MSG_WAIT_CONFIRMATION;

                // Таймер готовности сообщения к отправке
                msg->_sending_time = (uint32_t)(clock() * (1000.0 /CLOCKS_PER_SEC));
                // TODO надо ли возвращать именно RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION
                if (msg->confirmation_flag)
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION;
                }
                else if (msg->state & RF62X_MSG_ENCODED)
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA_READY;
                }else
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA;
                }
            }
            else if (parser->output_msg_buffer[parser->output_msg_index].data_pos >=
                        (uint32_t)(msg->data_size))
            {
                if (msg->state & RF62X_MSG_WAIT_CONFIRMATION)
                {
                    if ((clock() * (1000.0 /CLOCKS_PER_SEC) - msg->_sending_time) <
                            msg->_timeout)
                    {
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION;
                    }else
                    {
                        // TODO Нужно ли только в одном месте чистить сообщения
//                        msg->_timeout_clb(parser->output_msg_buffer[parser->output_msg_index].msg);
//                        msg->state |= RF62X_MSG_TIMEOUT;
                        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                        return RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT;
                    }
                }

                // TODO нужно ли контролировать время отправки данных
//                if (parser->output_msg_buffer[parser->output_msg_index].msg->_timeout > 0)
//                {
//                    if ((clock() - parser->output_msg_buffer[parser->output_msg_index].msg->_sending_time) >
//                            parser->output_msg_buffer[parser->output_msg_index].msg->_timeout)
//                    {
//                        parser->output_msg_buffer[parser->output_msg_index].msg->_timeout_clb(
//                                    parser->output_msg_buffer[parser->output_msg_index].msg);
//                        parser->output_msg_buffer[parser->output_msg_index].msg->state |= RF62X_MSG_TIMEOUT;
//                        return RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT;
//                    }
//                }

                // Return DATA packet flag
                if (msg->confirmation_flag)
                    msg->state |= RF62X_MSG_WAIT_CONFIRMATION;

                // Если сообщение полностью закодировано, то добавить соответствующие флаги
                msg->state = RF62X_MSG_ENCODED;
                if (msg->wait_answ_flag)
                    msg->state |= RF62X_MSG_WAIT_ANSW;

                // Таймер готовности сообщения к отправке
                msg->_sending_time = (uint32_t)(clock() * (1000.0 /CLOCKS_PER_SEC));
                // TODO надо ли возвращать именно RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION
                if (msg->confirmation_flag)
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION;
                }
                else if (msg->state & RF62X_MSG_ENCODED)
                {
                    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
                    return RF62X_PARSER_RETURN_STATUS_DATA_READY;
                }
            }
        }


        // Return DATA_READY information
        packet_size = 0;
    }else if (msg->state & RF62X_MSG_WAIT_CONFIRMATION)
    {
        if ((clock() * (1000.0 /CLOCKS_PER_SEC) - msg->_sending_time) <
                msg->_timeout)
        {
            pthread_mutex_unlock(&parser->output_msg_buff_mutex);
            return RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION;
        }else
        {
            // TODO Нужно ли только в одном месте чистить сообщения
            //msg->_timeout_clb(parser->output_msg_buffer[parser->output_msg_index].msg);
            //msg->state |= RF62X_MSG_TIMEOUT;
            pthread_mutex_unlock(&parser->output_msg_buff_mutex);
            return RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT;
        }
    }
    else if (msg->state & RF62X_MSG_TIMEOUT)
    {
        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
        return RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT;
    }else if (msg->state & RF62X_MSG_ENCODED &&
              msg->state & RF62X_MSG_WAIT_ANSW)
    {
        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
        *packet_size = 0;
        return RF62X_PARSER_RETURN_STATUS_DATA_READY;
    }
    else if (msg->state & RF62X_MSG_ENCODED)
    {
        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
        *packet_size = 0;
        return RF62X_PARSER_RETURN_STATUS_DATA_READY;
    }
    pthread_mutex_unlock(&parser->output_msg_buff_mutex);
    return RF62X_PARSER_RETURN_STATUS_NO_DATA;

}

RF62X_msg_t* RF62X_parser_get_msg(RF62X_parser_t *parser, int32_t timeout)
{

    const int lock_rv = pthread_mutex_lock(&parser->input_msg_buff_mutex);
    if (lock_rv)
    {
        error_pthread_mutex_lock(lock_rv);
        return FALSE;
    }

    for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
    {
//        parser->input_msg_index = (parser->input_msg_index + 1) % RF62X_PARSER_INPUT_BUFFER_QUEUE;
        RF62X_msg_t* input_msg = parser->input_msg_buffer[i].msg;

        if (input_msg->state & RF62X_MSG_WAIT_READING)
        {
            RF62X_msg_t* return_msg = RF62X_create_rqst_msg(
                        input_msg->cmd_name, input_msg->data, input_msg->data_size, input_msg->type,
                        input_msg->check_crc_flag, input_msg->confirmation_flag, TRUE,
                        0,
                        NULL, NULL, NULL);

            return_msg->_uid = input_msg->_uid;
            // Reset data ready flag
            input_msg->state ^= RF62X_MSG_WAIT_READING;
            input_msg->state |= RF62X_MSG_READ;

            parser->input_data_cond_var_flag = FALSE;

            // Unlock and return
            pthread_mutex_unlock(&parser->input_msg_buff_mutex);
            return return_msg;
        }
    }

    pthread_mutex_unlock(&parser->input_msg_buff_mutex);


    // If timeout == 0 then we need only check data precense (we did it before)
    if (timeout == 0)
        return FALSE;

    // Wait data
    if (timeout == -1)
    {
        // We wait endlessly until the new data arrives.
        pthread_mutex_lock(&parser->input_data_cond_var_mutex);
        while (!parser->input_data_cond_var_flag)
            pthread_cond_wait(&parser->input_data_cond_var, &parser->input_data_cond_var_mutex);
        parser->input_data_cond_var_flag = FALSE;
        pthread_mutex_unlock(&parser->input_data_cond_var_mutex);
    }
    else
    {
        // Wait only indicated time.
        pthread_mutex_lock(&parser->input_data_cond_var_mutex);
        // timespec is a structure holding an interval broken down into seconds and nanoseconds.
        struct timespec max_wait = {0, 0};

        const int gettime_rv = clock_gettime(CLOCK_REALTIME, &max_wait);
        if (gettime_rv)
        {
            error_clock_gettime(gettime_rv);
            return FALSE;
        }else
        {
            max_wait.tv_sec += timeout / 1000;      // 2 sec
            max_wait.tv_nsec += ((timeout % 1000) * 1000) * 1000; // nsec
            while (!parser->input_data_cond_var_flag)
            {
                const int timed_wait_rv = pthread_cond_timedwait(&parser->input_data_cond_var, &parser->input_data_cond_var_mutex, &max_wait);
                if (timed_wait_rv)
                {
//                    error_pthread_cond_timedwait(timed_wait_rv);
                    pthread_mutex_unlock(&parser->input_data_cond_var_mutex);
                    return FALSE;
                }
            }
            parser->input_data_cond_var_flag = FALSE;
            pthread_mutex_unlock(&parser->input_data_cond_var_mutex);
        }
    }   

    // Check data pressence egain.
    const int lock_ib = pthread_mutex_lock(&parser->input_msg_buff_mutex);
    if (lock_ib)
    {
        error_pthread_mutex_lock(lock_rv);
        return FALSE;
    }

    for (int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
    {
//        parser->input_msg_index = (parser->input_msg_index + 1) % RF62X_PARSER_INPUT_BUFFER_QUEUE;
        RF62X_msg_t* input_msg = parser->input_msg_buffer[i].msg;

        if (input_msg->state & RF62X_MSG_WAIT_READING)
        {
            RF62X_msg_t* return_msg = RF62X_create_rqst_msg(
                        input_msg->cmd_name, input_msg->data, input_msg->data_size, input_msg->type,
                        input_msg->check_crc_flag, input_msg->confirmation_flag, TRUE,
                        0,
                        NULL, NULL, NULL);

            return_msg->_uid = input_msg->_uid;
            // Reset data ready flag
            input_msg->state ^= RF62X_MSG_WAIT_READING;
            input_msg->state |= RF62X_MSG_READ;

            parser->input_data_cond_var_flag = FALSE;

            // Unlock and return
            pthread_mutex_unlock(&parser->input_msg_buff_mutex);
            return return_msg;
        }
    }

    pthread_mutex_unlock(&parser->input_msg_buff_mutex);

    // Return FALSE if no data.
    return NULL;
}

uint8_t RF62X_parser_cleanup(RF62X_parser_t *parser)
{
#ifdef _WIN32
    if (parser->output_msg_buff_mutex != NULL)
    {
#endif
        pthread_mutex_lock(&parser->output_msg_buff_mutex);
        if (parser->output_msg_buffer != NULL)
        {
            for(int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
            {
                if (parser->output_msg_buffer[i].msg != NULL)
                {
                    if (parser->output_msg_buffer[i].msg->state & RF62X_MSG_ANSWERED &&
                            parser->output_msg_buffer[i].msg->_free_clb != NULL)
                    {
                        parser->output_msg_buffer[i].msg->_free_clb(parser->output_msg_buffer[i].msg);
                    }
                    RF62X_cleanup_msg(parser->output_msg_buffer[i].msg);
                    free(parser->output_msg_buffer[i].msg);
                    parser->output_msg_buffer[i].msg = NULL;
                }
            }
            free(parser->output_msg_buffer);
            parser->output_msg_buffer = NULL;
        }
        pthread_mutex_unlock(&parser->output_msg_buff_mutex);
#ifdef _WIN32
    }
#endif

#ifdef _WIN32
    if (parser->input_msg_buff_mutex != NULL)
    {
#endif
        pthread_mutex_lock(&parser->input_msg_buff_mutex);
        if (parser->input_msg_buffer != NULL)
        {
            for(int i = 0; i < RF62X_PARSER_INPUT_BUFFER_QUEUE; i++)
            {
                if (parser->input_msg_buffer[i].msg != NULL)
                {
                    RF62X_cleanup_msg(parser->input_msg_buffer[i].msg);
                    free(parser->input_msg_buffer[i].msg);
                    parser->input_msg_buffer[i].msg = NULL;
                }
            }
            free(parser->input_msg_buffer);
            parser->input_msg_buffer = NULL;
        }
        pthread_mutex_unlock(&parser->input_msg_buff_mutex);
#ifdef _WIN32
    }
#endif

//    pthread_mutex_destroy(&parser->input_data_cond_var);
#ifdef _WIN32
    if (parser->input_data_cond_var_mutex)
        pthread_mutex_destroy(&parser->input_data_cond_var_mutex);
    if (parser->input_wait_confirm_var_mutex)
        pthread_mutex_destroy(&parser->input_wait_confirm_var_mutex);
    if (parser->input_msg_buff_mutex)
        pthread_mutex_destroy(&parser->input_msg_buff_mutex);
    if (parser->output_msg_buff_mutex)
        pthread_mutex_destroy(&parser->output_msg_buff_mutex);

#else
    pthread_mutex_destroy(&parser->input_data_cond_var_mutex);
    pthread_mutex_destroy(&parser->input_wait_confirm_var_mutex);
    pthread_mutex_destroy(&parser->input_msg_buff_mutex);
    pthread_mutex_destroy(&parser->output_msg_buff_mutex);
#endif

    return TRUE;
}

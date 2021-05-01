#include "smartchannel.h"
#include "smartutils.h"
#include "smartparser.h"


#include <mpack/mpack.h>
#include <string.h>
#include <stdio.h>
//#include <pthread.h>


#include <time.h>

#ifdef _WIN32
#include <Windows.h>
#include <winsock.h>
#include <stdint.h>
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
}smart_channel_init_param_t;


char *smart_channel_version()
{
    char* version = "1.1.4";
    return version;
}

uint8_t test_msg_uid = 1;
uint8_t test_uid = 1;
void *read_thread_func (void *args) {
    smart_channel* channel = args;

    // Allocate memory
    int bytes = 0;				///< Number of readed bytes.
    //char logic_port[256];		///< Logoc port of input data.
    int32_t result_value = 0;	///< Result value of methods.
    uint16_t packet_size = 0;	///< Packet size
    uint8_t* packet_data = calloc(channel->max_packet_size, sizeof (uint8_t));

    // Thread loop
    while (!channel->thread_stop_flag)
    {

        const int lock_rv = pthread_mutex_lock(&channel->smart_parser.output_msg_buff_mutex);
        if (lock_rv)
        {
            error_pthread_mutex_lock(lock_rv);
            return FALSE;
        }

        // Checking timeout
        for (int i = 0; i < SMART_PARSER_OUTPUT_BUFFER_QUEUE; i++)
        {
            smart_msg_t* msg = channel->smart_parser.output_msg_buffer[i].msg;
            if (msg->state & SMART_MSG_ENCODED && msg->_sending_time != 0)
            {
                if ((clock() * (1000.0 /CLOCKS_PER_SEC) - msg->_sending_time) > msg->_timeout &&
                        ((msg->state & SMART_MSG_TIMEOUT) == FALSE))
                {
                    // TODO Нужно ли только в одном месте чистить сообщения
                    msg->state |= SMART_MSG_TIMEOUT;
                }
            }
        }
        pthread_mutex_unlock(&channel->smart_parser.output_msg_buff_mutex);
#ifndef TEST_SENDER
//------Original-----------------------------------------------------------------------------------------------
        // Wait input data (default timeout = 100 ms)
        struct sockaddr_in* srcSockaddr = NULL;
        bytes = udp_port_read_data(&channel->smart_sock, packet_data, channel->max_packet_size, srcSockaddr);
#else
//------Test---------------------------------------------------------------------------------------------------
        char datatest[10] = {1,2,3,4,5,6,7,8,9,10};
        // encode to memory buffer
        mpack_writer_t writer;
        char* test_packet = NULL;
        mpack_writer_init_growable(&writer, &test_packet, &bytes);

        // write the example on the msgpack homepage
        mpack_start_map(&writer, 2);
        {
            // Идентификатор сообщения
            mpack_write_cstr(&writer, "msg_uid"); mpack_write_uint(&writer, test_msg_uid++);

            // Сообщение
            mpack_write_cstr(&writer, "msg"); mpack_start_map(&writer, 5);
            {
                // Тип команды: rqst - запрос, answ - ответ
                mpack_write_cstr(&writer, "type"); mpack_write_cstr(&writer, "rqst");

                // Логический порт (обработчик команды)
                mpack_write_cstr(&writer, "name"); mpack_write_cstr(&writer, "test_cmd");

                // Идентификатор команды. В случае с цепочкой все сообщения одной команды имеют одинаковый uid
                mpack_write_cstr(&writer, "uid"); mpack_write_uint(&writer, test_uid++);

                // Тип содержимого - chunk, payload
                mpack_write_cstr(&writer, "content_type"); mpack_write_cstr(&writer, "chunk");

                mpack_write_cstr(&writer, "chunk"); mpack_start_map(&writer, 5);
                {
                    // Если присутствует - указывает, каким протоколом упакованы данные в цепочке, если нет - сырые данные
                    // mpack_write_cstr(&writer, "container_type"); mpack_write_cstr(&writer, "mpack");

                    // Полный размер
                    mpack_write_cstr(&writer, "chain_size"); mpack_write_uint(&writer, sizeof (datatest));

                    // crc-16
                    mpack_write_cstr(&writer, "chain_crc16"); mpack_write_uint(&writer, 0);

                    // Смещение фрагмента данных в цепочке
                    mpack_write_cstr(&writer, "offset"); mpack_write_uint(&writer, 0);

                    // Флаг последнего фрагмента
                    mpack_write_cstr(&writer, "last"); mpack_write_bool(&writer, TRUE);

                    // Бинарные данные
                    mpack_write_cstr(&writer, "data"); mpack_write_bin(&writer, datatest, sizeof (datatest));

                }
                mpack_finish_map(&writer);
            }
            mpack_finish_map(&writer);
        }
        mpack_finish_map(&writer);

        // finish writing
        if (mpack_writer_destroy(&writer) != mpack_ok) {
            fprintf(stderr, "An error occurred encoding the data!\n");
            return FALSE;
        }

        memcpy(packet_data, test_packet, bytes);
        free(test_packet);
//-------------------------------------------------------------------------------------------------------------
#endif
        // Check new data precense.
        if (bytes > 0)
        {
            // Decode input packet.
            result_value = smart_parser_decode_msg(&channel->smart_parser,
                        packet_data, (uint16_t)bytes);

            // Check result.
            switch (result_value)
            {
            // Check if it LOST DATA REQUEST.
            case SMART_PARSER_RETURN_STATUS_LOST_DATA_REQUEST:
            {
                // Encode and send packets with lost data.
//                do
//                {
//                    // Encode next packet with lost data.
//                    result_value = smart_parser_encode_lost_data_packet(&channel->smart_parser, packet_data, &packet_size);
//                    if (result_value == SMART_PARSER_RETURN_STATUS_DATA)
//                    {
//                        // Send packet.
//                        pthread_mutex_lock(&channel->output_udpport_mutex);
//                        udp_port_send_data(&channel->smart_sock, packet_data, packet_size);
//                        pthread_mutex_unlock(&channel->output_udpport_mutex);
//                    }

//                } while (result_value == SMART_PARSER_RETURN_STATUS_DATA);
            }
                break;

                // Check if new data arrived.
            case SMART_PARSER_RETURN_STATUS_DATA_READY:
            {
                // Get DATA_CONFIRMATION packet.
                uint16_t data_size = 0;
                smart_parser_get_msg_confirmation_packet(&channel->smart_parser, packet_data, &data_size);

                // Send DATA_CONFIRMATION packet.
                if (data_size > 0)
                {
                    //pthread_mutex_lock(&channel->output_udpport_mutex);
                    udp_port_send_data(&channel->smart_sock, packet_data, data_size);
                    //pthread_mutex_unlock(&channel->output_udpport_mutex);
                }
            }
                break;

                // Check if new data arrived.
            case SMART_PARSER_RETURN_STATUS_DATA_CONFIRMATION:
            {
                // Get DATA_CONFIRMATION packet.
                uint16_t data_size = 0;
                smart_parser_get_msg_confirmation_packet(&channel->smart_parser, packet_data, &data_size);

                // Send DATA_CONFIRMATION packet.
                if (data_size > 0)
                {
                    //pthread_mutex_lock(&channel->output_udpport_mutex);
                    udp_port_send_data(&channel->smart_sock, packet_data, data_size);
                    //pthread_mutex_unlock(&channel->output_udpport_mutex);
                }
            }
                break;

            case SMART_PARSER_RETURN_STATUS_LOST_DATA_DETECTED:
            {
                // Get LOST_DATA_REQUEST packet.
                uint16_t data_size = 0;
                //smart_parser_get_lost_data_request_packet(&channel->smart_parser, packet_data, &data_size);

                // Send LOST_DATA_REQUEST packet.
//                pthread_mutex_lock(&channel->output_udpport_mutex);
//                udp_port_send_data(&channel->smart_sock, packet_data, data_size);
//                pthread_mutex_unlock(&channel->output_udpport_mutex);
            }
                break;

            default:
                break;
            }
        }else
        {
            printf("no data has been received\n");
        }
    }

    free(packet_data); packet_data = NULL;

    return 0;
}

uint8_t smart_channel_init(smart_channel* channel, char *init_string)
{
    // Preparation smart_channel for initialization
    memset(channel, 0, sizeof (smart_channel));
    channel->output_packet_data = NULL;
    channel->thread_stop_flag = FALSE;

    pthread_mutex_init(&channel->instance_mutex, NULL);
    pthread_mutex_init(&channel->output_udpport_mutex, NULL);
    pthread_mutex_init(&channel->global_mutex, NULL);


    // Lock global mutex to prevent access from multiple threads.
    pthread_mutex_lock(&channel->global_mutex);

    // Read init_string and Set params to variabes.
    if (strlen(init_string) > 0)
    {
        // Parse parameters.
        int _str_len = strlen(init_string) + 1;
        char* _init_string = calloc(_str_len, sizeof(char));

        memcpy(_init_string, init_string, _str_len);

        char *token;
        int param_count = 0;
        token = strtok(_init_string, "-");
        while (token != NULL)
        {
            param_count++;
            token=strtok(NULL,"-");
        }

        smart_channel_init_param_t* params = calloc(param_count, sizeof (smart_channel_init_param_t));

        memcpy(_init_string, init_string, _str_len);
        token = strtok(_init_string, " "); int token_len = 0;
        for (int i = 0; i < param_count; i++)
        {
            token_len = strlen(token) + 1;
            params[i].key = calloc(token_len, sizeof (char));
            memcpy(params[i].key, token, token_len);

            token = strtok(NULL, " "); token_len = strlen(token) + 1;
            params[i].value = calloc(token_len, sizeof (char));
            memcpy(params[i].value, token, token_len);

            token = strtok(NULL, " ");
        }

        // Set params to variabes.
        for(int i = 0; i < param_count; i++)
        {
            smart_channel_opt_set(channel, params[i].key, params[i].value);
            free(params[i].key); params[i].key = NULL;
            free(params[i].value); params[i].value = NULL;
        }

        free(_init_string);
        free(params);

    }

    // UDP Port initialization
    if (!udp_port_init(&channel->smart_sock))
    {
        return FALSE;
    }

    // Try open socket.
    udp_port_set_dst_ip(&channel->smart_sock, channel->dst_ip_addr);
    udp_port_set_host_ip(&channel->smart_sock, channel->host_ip_addr);
    if (!udp_port_open(&channel->smart_sock, channel->out_udp_port,
                       channel->socket_timeout, TRUE))
    {
        return FALSE;
    }

    // Parser initialization
    if (!smart_parser_init(&channel->smart_parser, init_string))
    {
        return FALSE;
    }


    // Allocate memory.
    channel->output_packet_data = calloc(channel->max_packet_size, sizeof (uint8_t));

    // Start thread.
    pthread_create(&channel->read_thread, NULL, read_thread_func, channel);

    pthread_mutex_unlock(&channel->global_mutex);
    return TRUE;
}


uint8_t smart_channel_cleanup(smart_channel *channel)
{
    channel->thread_stop_flag = TRUE;
    int status;
    status = pthread_join(channel->read_thread, NULL);
    if(channel->output_packet_data != NULL)
    {
        free (channel->output_packet_data); channel->output_packet_data = NULL;
    }
    smart_parser_cleanup(&channel->smart_parser);
    udp_port_cleanup(&channel->smart_sock);

#ifdef _WIN32
    if (channel->instance_mutex)
        pthread_mutex_destroy(&channel->instance_mutex);
    if (channel->output_udpport_mutex)
        pthread_mutex_destroy(&channel->output_udpport_mutex);
    if (channel->global_mutex)
        pthread_mutex_destroy(&channel->global_mutex);
#else
    pthread_mutex_destroy(&channel->instance_mutex);
    pthread_mutex_destroy(&channel->output_udpport_mutex);
    pthread_mutex_destroy(&channel->global_mutex);
#endif
    if (status != 0)
        return FALSE;
    else return TRUE;
}


uint8_t smart_channel_opt_set(smart_channel* channel, char *opt_name, char *val)
{
    if (0 == strcmp(opt_name, "-dst_ip_addr"))
    {
        ip_string_to_uint32(val, &channel->dst_ip_addr);
        return TRUE;
    }else if (0 == strcmp(opt_name, "-host_ip_addr"))
    {
        ip_string_to_uint32(val, &channel->host_ip_addr);
        return TRUE;
    }
    else if (0 == strcmp(opt_name, "-in_udp_port"))
    {
        string_to_uint16(val, &channel->in_udp_port);
        return TRUE;
    }
    else if (0 == strcmp(opt_name, "-out_udp_port"))
    {
        string_to_uint16(val, &channel->out_udp_port);
        return TRUE;
    }
    else if (0 == strcmp(opt_name, "-socket_timeout"))
    {
        string_to_uint32(val, &channel->socket_timeout);
        return TRUE;

    }else if (0 == strcmp(opt_name, "-max_packet_size"))
    {
        string_to_uint16(val, &channel->max_packet_size);
        return TRUE;

    }else if (0 == strcmp(opt_name, "-max_data_size"))
    {
        string_to_uint32(val, &channel->max_data_size);
        return TRUE;
    }
}

uint8_t smart_channel_send_msg(smart_channel *channel, smart_msg_t *msg)
{
    const int lock_rv = pthread_mutex_lock(&channel->instance_mutex);
    if (lock_rv)
    {
        error_pthread_mutex_lock(lock_rv);
        return FALSE;
    }

    if (!smart_parser_add_msg(&channel->smart_parser, msg))
    {
        pthread_mutex_unlock(&channel->instance_mutex);
        return FALSE;
    }

    // Init vars
    uint16_t packet_size = 0;
    int32_t result_value = SMART_PARSER_RETURN_STATUS_PARAMS_ERROR;

    // Sending loop
    while (result_value != SMART_PARSER_RETURN_STATUS_DATA_READY &&
           result_value != SMART_PARSER_RETURN_STATUS_NO_DATA)
    {
        // Encode data packet
        result_value = smart_parser_encode_msg(
                    &channel->smart_parser,
                    channel->output_packet_data,
                    &packet_size);

        // Check if encoding was unsuccessfull
        if (result_value == SMART_PARSER_RETURN_STATUS_DATA_TIMEOUT)
        {
            pthread_mutex_unlock(&channel->instance_mutex);
            return FALSE;
        }

        if (result_value == SMART_PARSER_RETURN_STATUS_NO_DATA)
        {
            pthread_mutex_unlock(&channel->instance_mutex);
            return FALSE;
        }

        // Send data
        if (packet_size > 0)
        {
            pthread_mutex_lock(&channel->output_udpport_mutex);
            int ret = udp_port_send_data(&channel->smart_sock, channel->output_packet_data, packet_size);
//            packet_size = 0;
            pthread_mutex_unlock(&channel->output_udpport_mutex);
            if (ret <= 0)
            {
                pthread_mutex_unlock(&channel->instance_mutex);
                return FALSE;
            }
        }


        if (result_value == SMART_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION)
        {
            clock_t goal = SMART_PARSER_DEFAULT_WAIT_CONFIRM_TIMEOUT + clock() * (1000.0 /CLOCKS_PER_SEC);
            while (goal > clock() * (1000.0 /CLOCKS_PER_SEC));
        }
    }

    pthread_mutex_unlock(&channel->instance_mutex);
    return TRUE;
}

smart_msg_t* smart_channel_get_msg(smart_channel *channel, int32_t timeout_ms)
{
    // Lock
    pthread_mutex_lock(&channel->instance_mutex);

    // Get or wait new input data.
    smart_msg_t* ret_msg = smart_parser_get_msg(&channel->smart_parser, timeout_ms);

    // UnLock
    pthread_mutex_unlock(&channel->instance_mutex);
    return ret_msg;
}

#ifdef _WIN32
void usleep(__int64 usec)
{
    HANDLE timer;
    LARGE_INTEGER ft;

    ft.QuadPart = -(10*usec); // Convert to 100 nanosecond interval, negative value indicates relative time

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);
}
#endif


void *smart_get_result_to_rqst_msg(smart_channel *channel, smart_msg_t *msg, uint32_t timeout)
{
    unsigned int mseconds = timeout;
    uint8_t is_answered = FALSE;
    clock_t goal = mseconds + clock() * (1000.0 /CLOCKS_PER_SEC);
    // Если ожидается только один ответ на запрос, то выполнять постоянную проверку на ответ
    if (msg->one_answ_flag)
    {
        while (goal > clock() * (1000.0 /CLOCKS_PER_SEC))
        {
            // Lock
            pthread_mutex_lock(&channel->smart_parser.output_msg_buff_mutex);
            if (channel->smart_parser.output_msg_buffer != NULL)
            {
                for (int i = 0; i < SMART_PARSER_OUTPUT_BUFFER_QUEUE; i++)
                {
                    smart_msg_t* rqst_msg = channel->smart_parser.output_msg_buffer[i].msg;
                    if ((rqst_msg != NULL) && (rqst_msg->_uid == msg->_uid))
                    {
                        if (rqst_msg->state & SMART_MSG_ANSWERED)
                        {
                            is_answered = TRUE;
                            pthread_mutex_unlock(&channel->smart_parser.output_msg_buff_mutex);
                            return rqst_msg->result;
                        }
                    }
                }
            }else
            {
                pthread_mutex_unlock(&channel->smart_parser.output_msg_buff_mutex);
                return NULL;
            }
            // UnLock
            pthread_mutex_unlock(&channel->smart_parser.output_msg_buff_mutex);

            usleep(mseconds/10);
        }
    }
    // Если ожидается получение нескольких сообщений, до дождаться окончания таймера
    else
    {
        int count = 0;
        while (goal > clock() * (1000.0 /CLOCKS_PER_SEC))
        {
            count++;
        }

        // Lock
        pthread_mutex_lock(&channel->smart_parser.output_msg_buff_mutex);
        if (channel->smart_parser.output_msg_buffer != NULL)
        {
            for (int i = 0; i < SMART_PARSER_OUTPUT_BUFFER_QUEUE; i++)
            {
                smart_msg_t* rqst_msg = channel->smart_parser.output_msg_buffer[i].msg;
                if ((rqst_msg != NULL) && (rqst_msg->_uid == msg->_uid))
                {
                    if (rqst_msg->state)
                    {
                        is_answered = TRUE;
                        pthread_mutex_unlock(&channel->smart_parser.output_msg_buff_mutex);
                        return rqst_msg->result;
                    }
                }
            }
        }else
        {
            pthread_mutex_unlock(&channel->smart_parser.output_msg_buff_mutex);
            return NULL;
        }
        // UnLock
        pthread_mutex_unlock(&channel->smart_parser.output_msg_buff_mutex);

    }
    return NULL;
}

#include "RF62Xchannel.h"
#include "RF62Xparser.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

#include "mpack/mpack.h"
#include "utils.h"







typedef struct
{
    char* key;
    char* value;
}RF62X_channel_init_param_t;


char *RF62X_channel_version()
{
    char* version = "2.3.3";
    return version;
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

uint8_t test_msg_uid = 1;
uint8_t test_uid = 1;
void *read_thread_func (void *args) {
    RF62X_channel_t* channel = args;

    // Allocate memory
    int bytes = 0;				///< Number of readed bytes.
    //char logic_port[256];		///< Logoc port of input data.
    int32_t result_value = 0;	///< Result value of methods.
    uint8_t* packet_data = calloc(channel->max_packet_size, sizeof (uint8_t));

    // Thread loop
    while (!channel->thread_stop_flag)
    {

        const int lock_rv = pthread_mutex_lock(&channel->RF62X_parser.output_msg_buff_mutex);
        if (lock_rv)
        {
            error_pthread_mutex_lock(lock_rv);
            return FALSE;
        }

        // Checking timeout
        for (int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
        {
            RF62X_msg_t* msg = channel->RF62X_parser.output_msg_buffer[i].msg;
            if (msg->state & RF62X_MSG_ENCODED && msg->state & RF62X_MSG_WAIT_ANSW && msg->_sending_time != 0)
            {
                if ((clock() * (1000.0 /CLOCKS_PER_SEC) - msg->_sending_time) > msg->_timeout &&
                        ((msg->state & RF62X_MSG_TIMEOUT) == FALSE))
                {
                    // TODO Нужно ли только в одном месте чистить сообщения
                    msg->state |= RF62X_MSG_TIMEOUT;
                }
            }
        }
        pthread_mutex_unlock(&channel->RF62X_parser.output_msg_buff_mutex);

        // Wait input data (default timeout = 100 ms)
        struct sockaddr_in srcSockaddr = {0};
        bytes = udp_port_read_data(&channel->RF62X_sock, packet_data, channel->max_packet_size, &srcSockaddr);
        // Check new data precense.
        if (bytes > 0)
        {
            if (channel->dst_udp_port == 0)
            {
                channel->RF62X_sock.output_addr.sin_port = srcSockaddr.sin_port;
                channel->RF62X_sock.output_addr.sin_addr = srcSockaddr.sin_addr;
                channel->RF62X_sock.output_addr.sin_family = srcSockaddr.sin_family;
            }
            // Decode input packet.
            result_value = RF62X_parser_decode_msg(&channel->RF62X_parser,
                        packet_data, (uint16_t)bytes);

            // Check result.
            switch (result_value)
            {
            // Check if it LOST DATA REQUEST.
            case RF62X_PARSER_RETURN_STATUS_LOST_DATA_REQUEST:
            {
                // Encode and send packets with lost data.
//                do
//                {
//                    // Encode next packet with lost data.
//                    result_value = RF62X_parser_encode_lost_data_packet(&channel->RF62X_parser, packet_data, &packet_size);
//                    if (result_value == RF62X_PARSER_RETURN_STATUS_DATA)
//                    {
//                        // Send packet.
//                        pthread_mutex_lock(&channel->output_udpport_mutex);
//                        udp_port_send_data(&channel->RF62X_sock, packet_data, packet_size);
//                        pthread_mutex_unlock(&channel->output_udpport_mutex);
//                    }

//                } while (result_value == RF62X_PARSER_RETURN_STATUS_DATA);
            }
                break;

                // Check if new data arrived.
            case RF62X_PARSER_RETURN_STATUS_DATA_READY:
            {
                // Get DATA_CONFIRMATION packet.
                uint16_t data_size = 0;
                RF62X_parser_get_msg_confirmation_packet(&channel->RF62X_parser, packet_data, &data_size);

                // Send DATA_CONFIRMATION packet.
                if (data_size > 0)
                {
                    //pthread_mutex_lock(&channel->output_udpport_mutex);
                    udp_port_send_data(&channel->RF62X_sock, packet_data, data_size);
                    //pthread_mutex_unlock(&channel->output_udpport_mutex);
                }
            }
                break;

                // Check if new data arrived.
            case RF62X_PARSER_RETURN_STATUS_DATA_CONFIRMATION:
            {
                // Get DATA_CONFIRMATION packet.
                uint16_t data_size = 0;
                RF62X_parser_get_msg_confirmation_packet(&channel->RF62X_parser, packet_data, &data_size);

                // Send DATA_CONFIRMATION packet.
                if (data_size > 0)
                {
                    //pthread_mutex_lock(&channel->output_udpport_mutex);
                    udp_port_send_data(&channel->RF62X_sock, packet_data, data_size);
                    //pthread_mutex_unlock(&channel->output_udpport_mutex);
                }
            }
                break;

            case RF62X_PARSER_RETURN_STATUS_LOST_DATA_DETECTED:
            {
                // Get LOST_DATA_REQUEST packet.
                uint16_t data_size = 0;
                //RF62X_parser_get_lost_data_request_packet(&channel->RF62X_parser, packet_data, &data_size);

                // Send LOST_DATA_REQUEST packet.
//                pthread_mutex_lock(&channel->output_udpport_mutex);
//                udp_port_send_data(&channel->RF62X_sock, packet_data, data_size);
//                pthread_mutex_unlock(&channel->output_udpport_mutex);
            }
                break;

            default:
                break;
            }
        }else
        {
            //printf("no data has been received\n");
        }
    }

    free(packet_data); packet_data = NULL;

    return 0;
}

uint8_t RF62X_channel_init(RF62X_channel_t* channel, char *init_string)
{

    if (channel == NULL)
        return FALSE;

    // Preparation RF62X_channel_t for initialization
    memset(channel, 0, sizeof (RF62X_channel_t));
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
        token = strtok(_init_string, "--");
        while (token != NULL)
        {
            param_count++;
            token=strtok(NULL,"--");
        }

        RF62X_channel_init_param_t* params = calloc(param_count, sizeof (RF62X_channel_init_param_t));

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
            RF62X_channel_opt_set(channel, params[i].key, params[i].value);
            free(params[i].key); params[i].key = NULL;
            free(params[i].value); params[i].value = NULL;
        }

        free(_init_string);
        free(params);

    }

    // UDP Port initialization
    if (!udp_port_init(&channel->RF62X_sock))
    {
        return FALSE;
    }

    // Try open socket.

    udp_port_set_host_ip(&channel->RF62X_sock, channel->host_ip_addr);

    // Init output net atributes.
    if (channel->host_udp_port != 0)
    {
        if (channel->dst_udp_port != 0)
        {
            udp_port_set_dst_ip(&channel->RF62X_sock, channel->dst_ip_addr);
            channel->RF62X_sock.output_addr.sin_port = htons(channel->dst_udp_port);
            channel->RF62X_sock.output_addr.sin_family = AF_INET;
        }

        if (!udp_port_open(&channel->RF62X_sock, channel->host_udp_port,
                           channel->socket_timeout, FALSE))
        {
            return FALSE;
        }
    }else
    {
        if (channel->dst_udp_port != 0)
        {
            udp_port_set_dst_ip(&channel->RF62X_sock, channel->dst_ip_addr);
            channel->RF62X_sock.output_addr.sin_port = htons(channel->dst_udp_port);
            channel->RF62X_sock.output_addr.sin_family = AF_INET;

            if (!udp_port_open(&channel->RF62X_sock, channel->dst_udp_port,
                               channel->socket_timeout, TRUE))
            {
                return FALSE;
            }
        }else
        {
            return FALSE;
        }
    }

    // Parser initialization
    if (!RF62X_parser_init(&channel->RF62X_parser, init_string))
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


uint8_t RF62X_channel_cleanup(RF62X_channel_t *channel)
{
    channel->thread_stop_flag = TRUE;
    int status;
    status = pthread_join(channel->read_thread, NULL);
    if(channel->output_packet_data != NULL)
    {
        free (channel->output_packet_data); channel->output_packet_data = NULL;
    }
    RF62X_parser_cleanup(&channel->RF62X_parser);
    udp_port_cleanup(&channel->RF62X_sock);

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


uint8_t RF62X_channel_opt_set(RF62X_channel_t* channel, char *opt_name, char *val)
{
    if (0 == strcmp(opt_name, "--dst_ip_addr"))
    {
        ip_string_to_uint32(val, &channel->dst_ip_addr);
        return TRUE;
    }else if (0 == strcmp(opt_name, "--host_ip_addr"))
    {
        ip_string_to_uint32(val, &channel->host_ip_addr);
        return TRUE;
    }
    else if (0 == strcmp(opt_name, "--host_udp_port"))
    {
        string_to_uint16(val, &channel->host_udp_port);
        return TRUE;
    }
    else if (0 == strcmp(opt_name, "--dst_udp_port"))
    {
        string_to_uint16(val, &channel->dst_udp_port);
        return TRUE;
    }
    else if (0 == strcmp(opt_name, "--socket_timeout"))
    {
        string_to_uint32(val, &channel->socket_timeout);
        return TRUE;

    }else if (0 == strcmp(opt_name, "--max_packet_size"))
    {
        string_to_uint16(val, &channel->max_packet_size);
        return TRUE;

    }else if (0 == strcmp(opt_name, "--max_data_size"))
    {
        string_to_uint32(val, &channel->max_data_size);
        return TRUE;
    }
}

bool timespec_compar(struct timespec a, struct timespec b)
{
    if (a.tv_sec == b.tv_sec)
        return a.tv_nsec > b.tv_nsec;
    else
        return a.tv_sec > b.tv_sec;
}

static inline uint32_t div_u64(uint64_t dividend, uint32_t divisor, uint64_t *remainder)
{
    uint32_t ret = 0;

    while (dividend >= divisor) {
        dividend -= divisor;
        ret++;
    }

    *remainder = dividend;

    return ret;
}

#define NSEC_PER_SEC  1000000000L
static inline void timespec_add_ns(struct timespec *a, uint64_t ns)
{
    a->tv_sec += div_u64(a->tv_nsec + ns, NSEC_PER_SEC, &ns);
    a->tv_nsec = ns;
}

uint8_t RF62X_channel_send_msg(RF62X_channel_t *channel, RF62X_msg_t *msg)
{
    const int lock_rv = pthread_mutex_lock(&channel->instance_mutex);
    if (lock_rv)
    {
        error_pthread_mutex_lock(lock_rv);
        return FALSE;
    }

    int index = RF62X_parser_add_msg(&channel->RF62X_parser, msg);
    if (index < 0)
    {
        pthread_mutex_unlock(&channel->instance_mutex);
        return FALSE;
    }

    // Init vars
    uint16_t packet_size = 0;
    int32_t result_value = RF62X_PARSER_RETURN_STATUS_PARAMS_ERROR;

    uint8_t* output_packet_data = calloc(channel->max_packet_size, sizeof (uint8_t));
    // Sending loop
    while (result_value != RF62X_PARSER_RETURN_STATUS_DATA_READY &&
           result_value != RF62X_PARSER_RETURN_STATUS_NO_DATA)
    {
        // Encode data packet
        result_value = RF62X_parser_encode_msg(
                    &channel->RF62X_parser,
                    output_packet_data,
                    &packet_size, index);

        // Check if encoding was unsuccessfull
        if (result_value == RF62X_PARSER_RETURN_STATUS_DATA_TIMEOUT)
        {
            pthread_mutex_unlock(&channel->instance_mutex);
            free(output_packet_data);
            return FALSE;
        }

        if (result_value == RF62X_PARSER_RETURN_STATUS_NO_DATA)
        {
            pthread_mutex_unlock(&channel->instance_mutex);
            free(output_packet_data);
            return FALSE;
        }

        // Send data
        if (packet_size > 0)
        {
            pthread_mutex_lock(&channel->output_udpport_mutex);
            int ret = udp_port_send_data(&channel->RF62X_sock, output_packet_data, packet_size);
//            packet_size = 0;
            pthread_mutex_unlock(&channel->output_udpport_mutex);
            if (ret <= 0)
            {
                pthread_mutex_unlock(&channel->instance_mutex);
                free(output_packet_data);
                return FALSE;
            }
        }


        if (result_value == RF62X_PARSER_RETURN_STATUS_DATA_WAIT_CONFIRMATION)
        {
            // Wait only indicated time.
            pthread_mutex_lock(&channel->RF62X_parser.input_wait_confirm_var_mutex);
            // timespec is a structure holding an interval broken down into seconds and nanoseconds.
            struct timespec max_wait = {0, 0};

            const int gettime_rv = clock_gettime(CLOCK_REALTIME, &max_wait);
            if (gettime_rv)
            {
                error_clock_gettime(gettime_rv);
                free(output_packet_data);
                return FALSE;
            }else
            {
                timespec_add_ns(&max_wait, (RF62X_PARSER_DEFAULT_WAIT_CONFIRM_TIMEOUT * 1000) * 1000);
                if (!channel->RF62X_parser.input_wait_confirm_cond_var_flag)
                {
                    const int timed_wait_rv = pthread_cond_timedwait(&channel->RF62X_parser.input_wait_confirm_cond_var, &channel->RF62X_parser.input_wait_confirm_var_mutex, &max_wait);
                    if (timed_wait_rv)
                    {
                        //error_pthread_cond_timedwait(timed_wait_rv);
                        pthread_mutex_unlock(&channel->RF62X_parser.input_wait_confirm_var_mutex);
                        result_value = RF62X_PARSER_RETURN_STATUS_PARAMS_ERROR;
                        continue;
                    }else
                    {
                        channel->RF62X_parser.input_wait_confirm_cond_var_flag = FALSE;
                        pthread_mutex_unlock(&channel->RF62X_parser.input_wait_confirm_var_mutex);
                        pthread_mutex_unlock(&channel->instance_mutex);
                        continue;
                    }
                }else
                {
                    channel->RF62X_parser.input_wait_confirm_cond_var_flag = FALSE;
                    pthread_mutex_unlock(&channel->RF62X_parser.input_wait_confirm_var_mutex);
                    pthread_mutex_unlock(&channel->instance_mutex);
                    continue;
                }
            }
//            clock_t goal = RF62X_PARSER_DEFAULT_WAIT_CONFIRM_TIMEOUT + clock() * (1000.0 /CLOCKS_PER_SEC);
//            while (goal > clock() * (1000.0 /CLOCKS_PER_SEC));
        }
    }

    free(output_packet_data);
    pthread_mutex_unlock(&channel->instance_mutex);
    return TRUE;
}

RF62X_msg_t* RF62X_channel_get_msg(RF62X_channel_t *channel, int32_t timeout_ms)
{
    // Lock
    pthread_mutex_lock(&channel->instance_mutex);

    // Get or wait new input data.
    RF62X_msg_t* ret_msg = RF62X_parser_get_msg(&channel->RF62X_parser, timeout_ms);

    // UnLock
    pthread_mutex_unlock(&channel->instance_mutex);
    return ret_msg;
}



void *RF62X_find_result_to_rqst_msg(RF62X_channel_t *channel, RF62X_msg_t *msg, uint32_t timeout)
{
    uint64_t mseconds = timeout;

    // timespec is a structure holding an interval broken down into seconds and nanoseconds.
    struct timespec goal = {0, 0};
    struct timespec current_time = {0, 0};
    const int gettime_goal = clock_gettime(CLOCK_REALTIME, &goal);
    if (gettime_goal)
    {
        error_clock_gettime(gettime_goal);
        return FALSE;
    }
    const int gettime_current_time = clock_gettime(CLOCK_REALTIME, &current_time);
    if (gettime_current_time)
    {
        error_clock_gettime(gettime_current_time);
        return FALSE;
    }

    timespec_add_ns(&goal, (mseconds * 1000) * 1000);

    // Если ожидается только один ответ на запрос, то выполнять постоянную проверку на ответ
    if (msg->one_answ_flag)
    {
        //while (goal > clock() * (1000.0 /CLOCKS_PER_SEC))
        while (timespec_compar(goal, current_time))
        {
            const int gettime_current_time = clock_gettime(CLOCK_REALTIME, &current_time);
            if (gettime_current_time)
            {
                error_clock_gettime(gettime_current_time);
                return FALSE;
            }
            // Lock
//            pthread_mutex_lock(&channel->RF62X_parser.output_msg_buff_mutex);
            if (channel->RF62X_parser.output_msg_buffer != NULL)
            {
                for (int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
                {
                    RF62X_msg_t* rqst_msg = channel->RF62X_parser.output_msg_buffer[i].msg;
                    if ((rqst_msg != NULL) && (rqst_msg->_uid == msg->_uid))
                    {
                        if (rqst_msg->state & RF62X_MSG_ANSWERED)
                        {
//                            pthread_mutex_unlock(&channel->RF62X_parser.output_msg_buff_mutex);
                            return rqst_msg->result;
                        }
                    }
                }
            }else
            {
//                pthread_mutex_unlock(&channel->RF62X_parser.output_msg_buff_mutex);
                return NULL;
            }
            // UnLock
//            pthread_mutex_unlock(&channel->RF62X_parser.output_msg_buff_mutex);

            usleep(1000);
        }
    }
    // Если ожидается получение нескольких сообщений, до дождаться окончания таймера
    else
    {
//        int count = 0;
//        while (goal > clock() * (1000.0 /CLOCKS_PER_SEC))
//        {
//            count++;
//        }
        usleep(mseconds*1000);

        // Lock
//        pthread_mutex_lock(&channel->RF62X_parser.output_msg_buff_mutex);
        if (channel->RF62X_parser.output_msg_buffer != NULL)
        {
            for (int i = 0; i < RF62X_PARSER_OUTPUT_BUFFER_QUEUE; i++)
            {
                RF62X_msg_t* rqst_msg = channel->RF62X_parser.output_msg_buffer[i].msg;
                if ((rqst_msg != NULL) && (rqst_msg->_uid == msg->_uid))
                {
                    if (rqst_msg->state)
                    {
//                        pthread_mutex_unlock(&channel->RF62X_parser.output_msg_buff_mutex);
                        return rqst_msg->result;
                    }
                }
            }
        }else
        {
//            pthread_mutex_unlock(&channel->RF62X_parser.output_msg_buff_mutex);
            return NULL;
        }
        // UnLock
//        pthread_mutex_unlock(&channel->RF62X_parser.output_msg_buff_mutex);

    }
    return NULL;
}


int msg_count = 0;
RF62X_msg_t *RF62X_create_rqst_msg(char *cmd_name, char *data, uint32_t data_size, char* data_type,
                                   uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
                                   uint32_t timeout, uint32_t resends,
                                   RF62X_answ_callback answ_clb,
                                   RF62X_timeout_callback timeout_clb,
                                   RF62X_free_callback free_clb)
{
    RF62X_msg_t* rqst_msg = calloc(1, sizeof (RF62X_msg_t));

    strcpy(rqst_msg->type, "rqst");
    strcpy(rqst_msg->cmd_name, cmd_name);
    strcpy(rqst_msg->container_type, data_type);

    rqst_msg->check_crc_flag = is_check_crc;
    if (is_confirmation)
    {
        rqst_msg->confirmation_flag = TRUE;
        rqst_msg->_resends = resends;
    }else
    {
        rqst_msg->confirmation_flag = FALSE;
        rqst_msg->_resends = 0;
    }
    rqst_msg->one_answ_flag = is_one_answ;
    rqst_msg->wait_answ_flag = answ_clb == NULL? FALSE : TRUE;

    if (data_size > 0)
    {
        rqst_msg->data = calloc(data_size, sizeof (uint8_t));
        memcpy(rqst_msg->data, data, data_size);
        rqst_msg->data_size = data_size;
    }

    rqst_msg->_answ_clb = answ_clb;
    rqst_msg->_timeout_clb = timeout_clb;
    rqst_msg->_free_clb = free_clb;

    msg_count++;
    rqst_msg->_msg_uid = msg_count % (UINT64_MAX-1);//rand() % (UINT64_MAX-1) + 1;
    rqst_msg->_uid = msg_count % (UINT32_MAX-1);//rand() % (UINT_MAX-1) + 1;
    rqst_msg->_sending_time = 0;
    rqst_msg->_timeout = timeout;

    rqst_msg->state = RF62X_MSG_WAIT_ENCODING;

    rqst_msg->result = NULL;
    return rqst_msg;
}

RF62X_msg_t *RF62X_create_answ_msg(RF62X_msg_t* rqst_msg, char *data, uint32_t data_size, char* data_type,
                                   uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
                                   uint32_t timeout,  uint32_t resends,
                                   RF62X_answ_callback answ_clb,
                                   RF62X_timeout_callback timeout_clb,
                                   RF62X_free_callback free_clb)
{
    RF62X_msg_t* answ_msg = calloc(1, sizeof (RF62X_msg_t));

    strcpy(answ_msg->type, "answ");
    strcpy(answ_msg->cmd_name, rqst_msg->cmd_name);
    strcpy(answ_msg->container_type, data_type);

    answ_msg->check_crc_flag = is_check_crc;
    if (is_confirmation)
    {
        answ_msg->confirmation_flag = TRUE;
        answ_msg->_resends = resends;
    }else
    {
        answ_msg->confirmation_flag = FALSE;
        answ_msg->_resends = 0;
    }
    answ_msg->one_answ_flag = is_one_answ;
    answ_msg->wait_answ_flag = answ_clb == NULL? FALSE : TRUE;

    if (data_size > 0)
    {
        answ_msg->data = calloc(data_size, sizeof (uint8_t));
        memcpy(answ_msg->data, data, data_size);
        answ_msg->data_size = data_size;
    }

    answ_msg->_answ_clb = answ_clb;
    answ_msg->_timeout_clb = timeout_clb;
    answ_msg->_free_clb = free_clb;

    msg_count++;
    answ_msg->_msg_uid = msg_count % (UINT64_MAX-1);//rand() % (UINT64_MAX-1) + 1;
    answ_msg->_uid = rqst_msg->_uid;
    answ_msg->_sending_time = 0;
    answ_msg->_timeout = timeout;

    answ_msg->state = RF62X_MSG_WAIT_ENCODING;

    answ_msg->result = NULL;
    pthread_mutex_init(*rqst_msg->result_mutex, NULL);

    return answ_msg;
}

void RF62X_cleanup_msg(RF62X_msg_t *msg)
{
    if (msg != NULL)
    {
        memset(msg->type, 0, sizeof(msg->type));
        memset(msg->cmd_name, 0, sizeof(msg->cmd_name));
        memset(msg->container_type, 0, sizeof(msg->container_type));

        msg->check_crc_flag = FALSE;
        msg->confirmation_flag = FALSE;
        msg->wait_answ_flag = FALSE;
        msg->one_answ_flag = FALSE;

        if (msg->data != NULL)
        {
            free(msg->data); msg->data = NULL;
        }
        msg->data_size = 0;

        msg->_answ_clb = NULL;
        msg->_timeout_clb = NULL;
        msg->_free_clb = NULL;

        msg->_msg_uid = 0;
        msg->_device_id = 0;
        msg->_uid = 0;
        msg->_sending_time = 0;
        msg->_timeout = 0;

        msg->result = NULL;
        msg->state = RF62X_MSG_EMPTY;
    }
}


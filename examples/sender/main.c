#include "RF62Xchannel.h"
#include "RF62Xmsg.h"

#include <mpack/mpack.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>

#include<time.h>
void delay(unsigned int mseconds)
{
    clock_t goal = mseconds + clock();
    while (goal > clock());
}

/**
 * @brief RF62X_data_callback - callback is triggered when the data for
 * request has been received.
 * @param data Received data.
 * @param data_size Received data size.
 * @param data_device_id Device id that sent the reply.
 * @param rqst_msg Info about the request to which the response was received.
 * @return status (RF62X_PARSER_RETURN_STATUS_DATA_READY in case of successful)
 */
int8_t RF62X_data_callback(
        char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg);
/**
 * @brief RF62X_data_timeout_callback - callback is triggered when the
 * request timed out.
 * @param rqst_msg Info about the request to which the response was received.
 * @return status (RF62X_PARSER_RETURN_STATUS_DATA_READY in case of successful)
 */
int8_t RF62X_data_timeout_callback(void* rqst_msg);
/**
 * @brief RF62X_data_free_result_callback - callback is triggered when the
 * response to request has been received but not read
 * by user (RF62X_get_result_to_rqst_msg method).
 * @param rqst_msg Info about the request to which the response was received.
 * @return status (RF62X_PARSER_RETURN_STATUS_DATA_READY in case of successful)
 */
int8_t RF62X_data_free_result_callback(void* rqst_msg);


/**
 * @brief parse_cmd_line - parsing command line and validating passed arguments
 * @return valid config string in case of successful or NULL.
 */
char* parse_cmd_line(int argc,  char** argv);
/**
 * @brief get_default_config - return default string for demonstration example
 * @return valid config string.
 */
char* get_default_config();
/**
 * @brief generate_config_string - generate config string
 * @return config string.
 */
char* generate_config_string(
        uint32_t src_device_uid, char* dst_ip_addr, char* host_ip_addr,
        uint32_t in_udp_port, uint32_t out_udp_port, uint32_t socket_timeout,
        uint32_t max_packet_size, uint32_t max_data_size);


int main(int argc, char* argv[])
{
    printf("##############################\n");
    printf("#                            #\n");
    printf("#    Data Sender Test v2.0   #\n");
    printf("#                            #\n");
    printf("##############################\n\n");

    // Get RF62X-protocol version
    char* version = RF62X_channel_version();
    printf("RF62X-protocol version: %s\n\n", version);

    // Generate a config string from cmd-line or get default
    char* config = NULL;
    if (argc > 1)
    {
       config = parse_cmd_line(argc, argv);
       if (!config)
           return 0;
    }else
        config = get_default_config();


    // Protocol creation and initialization
    RF62X_channel channel;
    RF62X_channel_init(&channel, config);
    free(config);

    // Create short data msg for testing payload mode.
    char short_data[channel.max_packet_size / 2];
    memset(short_data, 1, sizeof (short_data));

    // Create long data msg for testing chain mode.
    char long_data[channel.max_packet_size * 500];
    memset(long_data, 2, sizeof (long_data));

    int32_t test_mode = 0;
    printf("Select the test payload mode \n"
           "0 - without payload, 1 - short payload msg, 2 - long payload msg: ");
    scanf("%d", &test_mode);


    printf("Start sending data...\n");
    int successful_results = 0;
    int rqst_count = 0;

    // Sending loop
    while (TRUE)
    {
        switch (test_mode) {
        //"test_without_payload"
        case 0:
        {
            // cmd_name - this is logical port/path where data will be send
            char* cmd_name                      = "WITHOUT_DATA_PORT";
            // payload - this is the data to be sent and their size
            char* payload                       = NULL;
            uint32_t payload_size               = 0;
            // data_type - this is the type of packaging of the sent data
            char* data_type                     = "blob";// mpack, json, blob..
            uint8_t is_check_crc                = FALSE; // check crc disabled
            uint8_t is_confirmation             = FALSE; // confirmation disabled
            uint8_t is_one_answ                 = TRUE;  // wait only one answer
            uint32_t waiting_time               = 1000;  // ms
            // callbacks for request
            RF62X_answ_callback answ_clb        = RF62X_data_callback;
            RF62X_timeout_callback timeout_clb  = RF62X_data_timeout_callback;
            RF62X_free_callback free_clb        = RF62X_data_free_result_callback;

            // Create request message
            RF62X_msg_t* msg = RF62X_create_rqst_msg(
                                    cmd_name, payload, payload_size, data_type,
                                    is_check_crc, is_confirmation, is_one_answ,
                                    waiting_time,
                                    answ_clb, timeout_clb, free_clb);
            // Send test msg
            if (!RF62X_channel_send_msg(&channel, msg))
                printf("Request was not sent. ");
            else
                printf("Requests %d were sent. ", ++rqst_count);


            // The struct of response to request.
            // User defines the type of response structure himself.
            typedef struct {
                char* received_data;
                int received_data_size;
            }answer_t;

            answer_t* result = RF62X_get_result_to_rqst_msg(&channel, msg, waiting_time);
            if (result != NULL)
            {
                if (strcmp("HELLO, SENDER!", result->received_data) == 0)
                {
                    // Cleanup test msg
                    RF62X_cleanup_msg(msg);
                    free(msg);
                    successful_results++;
                }else
                {
                    // Cleanup test msg
                    RF62X_cleanup_msg(msg);
                    free(msg);
                }
            }

            printf("Successfully %d responses received.\n", successful_results);
            break;
        }
        //"test_short_data"
        case 1:
        {
            // cmd_name - this is logical port/path where data will be send
            char* cmd_name                      = "SHORT_DATA_PORT";
            // payload - this is the data to be sent and their size
            char* payload                       = short_data;
            uint32_t payload_size               = sizeof (short_data);
            // data_type - this is the type of packaging of the sent data
            char* data_type                     = "blob";// mpack, json, blob..
            uint8_t is_check_crc                = FALSE; // check crc disabled
            uint8_t is_confirmation             = TRUE; // confirmation disabled
            uint8_t is_one_answ                 = TRUE;  // wait only one answer
            uint32_t waiting_time               = 1000;  // ms
            // callbacks for request
            RF62X_answ_callback answ_clb        = RF62X_data_callback;
            RF62X_timeout_callback timeout_clb  = RF62X_data_timeout_callback;
            RF62X_free_callback free_clb        = RF62X_data_free_result_callback;

            // Create request message
            RF62X_msg_t* msg = RF62X_create_rqst_msg(
                                    cmd_name, payload, payload_size, data_type,
                                    is_check_crc, is_confirmation, is_one_answ,
                                    waiting_time,
                                    answ_clb, timeout_clb, free_clb);

            // Send test msg
            if (!RF62X_channel_send_msg(&channel, msg))
                printf("Request was not sent. ");
            else
                printf("Requests %d were sent. ", ++rqst_count);


            // The struct of response to request.
            // User defines the type of response structure himself.
            typedef struct {
                char* received_data;
                int received_data_size;
            }answer_t;

            answer_t* result = RF62X_get_result_to_rqst_msg(&channel, msg, waiting_time);
            if (result != NULL)
            {
                if (strcmp("HELLO, SENDER!", result->received_data) == 0)
                {
                    // Cleanup test msg
                    RF62X_cleanup_msg(msg);
                    free(msg);
                    successful_results++;
                }else
                {
                    // Cleanup test msg
                    RF62X_cleanup_msg(msg);
                    free(msg);
                }
            }

            printf("Successfully %d responses received.\n", successful_results);
            break;
        }
        //"test_long_data"
        case 2:
        {
            // cmd_name - this is logical port/path where data will be send
            char* cmd_name                      = "LONG_DATA_PORT";
            // payload - this is the data to be sent and their size
            char* payload                       = long_data;
            uint32_t payload_size               = sizeof (long_data);
            // data_type - this is the type of packaging of the sent data
            char* data_type                     = "blob";// mpack, json, blob..
            uint8_t is_check_crc                = FALSE; // check crc disabled
            uint8_t is_confirmation             = FALSE; // confirmation disabled
            uint8_t is_one_answ                 = TRUE;  // wait only one answer
            uint32_t waiting_time               = 1000;  // ms
            // callbacks for request
            RF62X_answ_callback answ_clb        = RF62X_data_callback;
            RF62X_timeout_callback timeout_clb  = RF62X_data_timeout_callback;
            RF62X_free_callback free_clb        = RF62X_data_free_result_callback;

            // Create request message
            RF62X_msg_t* msg = RF62X_create_rqst_msg(
                                    cmd_name, payload, payload_size, data_type,
                                    is_check_crc, is_confirmation, is_one_answ,
                                    waiting_time,
                                    answ_clb, timeout_clb, free_clb);

            // Send test msg
            if (!RF62X_channel_send_msg(&channel, msg))
                printf("Request was not sent. ");
            else
                printf("Requests %d were sent. ", ++rqst_count);


            // The struct of response to request.
            // User defines the type of response structure himself.
            typedef struct {
                char* received_data;
                int received_data_size;
            }answer_t;

            answer_t* result = RF62X_get_result_to_rqst_msg(&channel, msg, waiting_time);
            if (result != NULL)
            {
                if (strcmp("HELLO, SENDER!", result->received_data) == 0)
                {
                    // Cleanup test msg
                    RF62X_cleanup_msg(msg);
                    free(msg);
                    successful_results++;
                }else
                {
                    // Cleanup test msg
                    RF62X_cleanup_msg(msg);
                    free(msg);
                }
            }

            printf("Successfully %d responses received.\n", successful_results);
            break;
        }
        default:
            break;
        }
    }
    return 0;
}



int8_t RF62X_data_callback(char* data, uint32_t data_size, uint32_t data_device_id, void* rqst_msg)
{
#ifdef _DEBUG
    printf("Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);
#endif
    int32_t status = RF62X_PARSER_RETURN_STATUS_NO_DATA;

    // You can check the ID of the device from which the response was received.
    uint32_t remote_device_id = 1;
    if (data_device_id == remote_device_id) {
        //response received from a known device...
    }else {
        //response received from unknown device...
    }


    // The following is an example of processing a response to a request
    // and packaging the return result into rqst_msg->result
    RF62X_msg_t* msg = rqst_msg;

    // result packing struct
    typedef struct {
        char* received_data;
        int received_data_size;
    }answer_t;

    if (msg->result == NULL) {
        msg->result = calloc(1, sizeof (answer_t));
    }

    answer_t* answer = msg->result;
    answer->received_data = calloc(data_size, sizeof (char));
    memcpy(answer->received_data, data, data_size);
    answer->received_data_size = data_size;

    status = RF62X_PARSER_RETURN_STATUS_DATA_READY;
    return status;
}
int8_t RF62X_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

#ifdef _DEBUG
    printf("Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);
#endif

    return TRUE;
}
int8_t RF62X_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

#ifdef _DEBUG
    printf("Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);
#endif

    if (msg->result != NULL)
    {
        // result packing struct
        typedef struct {
            char* received_data;
            int received_data_size;
        }answer_t;

        free(((answer_t*)msg->result)->received_data);
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}

char* parse_cmd_line(int argc,  char** argv)
{

    enum option_flag
    {
        SRC_DEVICE_UID = 0,
        DST_IP_ADDR,
        HOST_IP_ADDR,
        IN_UDP_PORT,
        OUT_UDP_PORT,
        SOCKET_TIMEOUT,
        MAX_PACKET_SIZE,
        MAX_DATA_SIZE,
    };

    const char* short_options = "?h";

    const struct option long_options[] = {
    {"help",no_argument,NULL,'h'},
    {"uid",required_argument,NULL,SRC_DEVICE_UID},
    {"dst",required_argument,NULL,DST_IP_ADDR},
    {"host",required_argument,NULL,HOST_IP_ADDR},
    {"in",required_argument,NULL,IN_UDP_PORT},
    {"out",required_argument,NULL,OUT_UDP_PORT},
    {"timeout",required_argument,NULL,SOCKET_TIMEOUT},
    {"ps",required_argument,NULL,MAX_PACKET_SIZE},
    {"ds",required_argument,NULL,MAX_DATA_SIZE},
    {NULL,0,NULL,0}
    };

    int rez;
    int option_index;

    uint32_t src_device_uid = 2;
    char* dst_ip_addr = "127.0.0.1";
    char* host_ip_addr = "127.0.0.1";
    uint32_t in_udp_port = 0;
    uint32_t out_udp_port = 50020;
    uint32_t socket_timeout = 100;
    uint32_t max_packet_size = 1024;
    uint32_t max_data_size = 1024 * 1024;

    while ((rez=getopt_long(argc,argv,short_options, long_options,&option_index))!=-1)
    {
        switch(rez)
        {
        case 'h':
        case '?':
        {
            printf(
                "Help information:\n"
                "-----------------\n"
                " --uid <src_device_uid>     Source device ID (\"2\" by default)\n"
                " --dst <dst_ip_addr>        Destination IP-addr (\"127.0.0.1\" by default)\n"
                " --host <host_ip_addr>      Host IP-addr (\"127.0.0.1\" by default)\n"
                " --in <in_udp_port>         Input UDP Port (\"0\" by default)\n"
                " --out <out_udp_port>       Output UDP Port (\"50020\" by default)\n"
                " --timeout <socket_timeout> Socket waiting time for data [ms] (\"100\" ms by default)\n"
                " --ps <max_packet_size>     Maximum UDP packet size [bytes] (\"1024\" bytes by default)\n"
                " --ds <max_data_size>       Maximum protocol packet size [bytes] (\"1048576\" bytes by default)\n"
                "\n"
                "An example command line would look like this:\n"
                "---------------------------------------------\n"
                " TestSender --dst 127.0.0.1 --out 50020\n"
            );
            return NULL;
            break;
        };
        case SRC_DEVICE_UID: {
            sscanf(optarg, "%d", &src_device_uid);
            break;
        };
        case DST_IP_ADDR: {
            dst_ip_addr = optarg;
            break;
        };
        case HOST_IP_ADDR: {
            host_ip_addr = optarg;
            break;
        };
        case IN_UDP_PORT: {
            sscanf(optarg, "%d", &in_udp_port);
            break;
        };
        case OUT_UDP_PORT: {
            sscanf(optarg, "%d", &out_udp_port);
            break;
        };
        case SOCKET_TIMEOUT: {
            sscanf(optarg, "%d", &socket_timeout);
            break;
        };
        case MAX_PACKET_SIZE: {
            sscanf(optarg, "%d", &max_packet_size);
            break;
        };
        case MAX_DATA_SIZE: {
            sscanf(optarg, "%d", &max_data_size);
            break;
        };
        default: {
            printf("found unknown option\n");
            break;
        };
        };


    }


    if (argc > 1)
    {
        printf("## INPUT SETTINGS ##\n\n"
               "src_device_uid\t: %d\n"
               "dst_ip_addr\t: %s\n"
               "host_ip_addr\t: %s\n"
               "in_udp_port\t: %d\n"
               "out_udp_port\t: %d\n"
               "socket_timeout\t: %d\n"
               "max_packet_size\t: %d\n"
               "max_data_size\t: %d\n\n",
               src_device_uid, dst_ip_addr, host_ip_addr, in_udp_port, out_udp_port,
               socket_timeout, max_packet_size, max_data_size);
    }

    return generate_config_string(
                src_device_uid, dst_ip_addr, host_ip_addr,
                in_udp_port, out_udp_port, socket_timeout,
                max_packet_size, max_data_size);

}

char* get_default_config()
{
    uint32_t src_device_uid = 2;
    char* dst_ip_addr = "127.0.0.1";
    char* host_ip_addr = "127.0.0.1";
    uint32_t in_udp_port = 0;
    uint32_t out_udp_port = 50020;
    uint32_t socket_timeout = 100;
    uint32_t max_packet_size = 1024;
    uint32_t max_data_size = 1024 * 1024;

    printf("## DEFAULT SETTINGS ##\n\n"
           "src_device_uid\t: %d\n"
           "dst_ip_addr\t: %s\n"
           "host_ip_addr\t: %s\n"
           "in_udp_port\t: %d\n"
           "out_udp_port\t: %d\n"
           "socket_timeout\t: %d\n"
           "max_packet_size\t: %d\n"
           "max_data_size\t: %d\n\n",
           src_device_uid, dst_ip_addr, host_ip_addr, in_udp_port, out_udp_port,
           socket_timeout, max_packet_size, max_data_size);

    return generate_config_string(
                src_device_uid, dst_ip_addr, host_ip_addr,
                in_udp_port, out_udp_port, socket_timeout,
                max_packet_size, max_data_size);
}

char* generate_config_string(
        uint32_t src_device_uid, char* dst_ip_addr, char* host_ip_addr,
        uint32_t in_udp_port, uint32_t out_udp_port, uint32_t socket_timeout,
        uint32_t max_packet_size, uint32_t max_data_size)
{
    char* config = calloc(1024, sizeof (char));

    sprintf(config,
            "--src_device_uid %d "
            "--dst_ip_addr %s "
            "--host_ip_addr %s "
            "--in_udp_port %d "
            "--out_udp_port %d "
            "--socket_timeout %d "
            "--max_packet_size %d "
            "--max_data_size %d",
            src_device_uid, dst_ip_addr, host_ip_addr, in_udp_port, out_udp_port,
            socket_timeout, max_packet_size, max_data_size);

    return config;
}


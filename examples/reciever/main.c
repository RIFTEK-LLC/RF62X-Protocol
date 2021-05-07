#include "RF62Xchannel.h"

#include <mpack/mpack.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>

#include <time.h>


/**
 * @brief RF62X_data_callback - callback is triggered when the data for
 * request has been received.
 * @param data Received data.
 * @param data_size Received data size.
 * @param data_device_id Device id that sent the reply.
 * @param rqst_msg Info about the request to which the response was received.
 * @return TRUE in case of successful
 */
int8_t RF62X_data_callback(
        char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg);
/**
 * @brief RF62X_data_timeout_callback - callback is triggered when the
 * request timed out.
 * @param rqst_msg Info about the request to which the response was received.
 * @return TRUE in case of successful
 */
int8_t RF62X_data_timeout_callback(void* rqst_msg);
/**
 * @brief RF62X_data_free_result_callback - callback is triggered when the
 * response to request has been received but not read
 * by user (RF62X_get_result_to_rqst_msg method).
 * @param rqst_msg Info about the request to which the response was received.
 * @return TRUE in case of successful
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
        uint32_t host_device_uid, char* host_ip_addr, char* dst_ip_addr,
        uint32_t host_udp_port, uint32_t dst_udp_port, uint32_t socket_timeout,
        uint32_t max_packet_size, uint32_t max_data_size);


int main(int argc, char* argv[])
{
    printf("##############################\n");
    printf("#                            #\n");
    printf("#   Data Reseiver Test v2.0  #\n");
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
    RF62X_channel_t channel;
    RF62X_channel_init(&channel, config);
    free(config);

    printf("Start recieving data...\n");
    clock_t start, end;
    start = clock();
    int answ_count = 0;

    // Reading loop
    while (TRUE)
    {
        // Wait data from channel with timeout of 5000 ms.
        RF62X_msg_t* msg = RF62X_channel_get_msg(&channel, 5000);
        if (msg != NULL)
        {
            // Calculate time between data.
            end = clock();
            double time_spent = (double)(end - start);

            // Print calculated bandwidth value.
            printf("Recieved %d bytes to %s during %lf ms\n", msg->data_size, msg->cmd_name, time_spent);
            start = clock();

            // You can check the command name (logical port/path) for which the
            // data was sent.
            if (strcmp("WITHOUT_DATA_PORT", msg->cmd_name) == 0) {
                //...
            }else if (strcmp("SHORT_DATA_PORT", msg->cmd_name) == 0) {
                //...
            }else if (strcmp("LONG_DATA_PORT", msg->cmd_name) == 0) {
                //...
            }
            // But in this example we will send the same response
            // for all requests.

            // Create test data answer.
            char* test_answer = "HELLO, SENDER!";

            // Create answ msg
            char* payload                      = test_answer;
            uint32_t payload_size              = strlen(test_answer);
            char* data_type                    = "blob";
            uint8_t is_check_crc               = FALSE; // check crc disabled
            uint8_t is_confirmation            = FALSE; // confirmation disabled
            uint8_t is_one_answ                = TRUE;  // wait only one answer
            uint32_t waiting_time              = 1000;  // ms
            // NULL in answ_clb means that any data in response will be ignored.
            RF62X_answ_callback answ_clb       = NULL;
            // After the timeout_clb has been triggered, which will indicate
            // that the response timed out for this message, free_clb will be
            // called to clear the possibly received data
            RF62X_timeout_callback timeout_clb = RF62X_data_timeout_callback;
            RF62X_free_callback free_clb       = RF62X_data_free_result_callback;

            RF62X_msg_t* answ_msg = RF62X_create_answ_msg(
                                          msg, payload, payload_size, data_type,
                                          is_check_crc, is_confirmation, is_one_answ,
                                          waiting_time,
                                          answ_clb, timeout_clb, free_clb);

            // Send answ msg
            if (!RF62X_channel_send_msg(&channel, answ_msg))
                printf("Answer was not sent. ");
            else
                printf("Answer %d were sent. ", answ_count++);

            // Cleanup answ msg
            RF62X_cleanup_msg(answ_msg);
            free(answ_msg);
            // Cleanup rqst msg
            RF62X_cleanup_msg(msg);
            free(msg);
        }else
        {
            printf("No data has been received.\n");
        }
    }

    return 0;
}


int8_t RF62X_data_callback(char* data, uint32_t data_size, uint32_t data_device_id, void* rqst_msg)
{
    printf("Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;

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

    status = TRUE;
    return status;
}
int8_t RF62X_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    printf("Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
int8_t RF62X_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    printf("Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

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
        HOST_DEVICE_UID = 0,
        HOST_IP_ADDR,
        HOST_UDP_PORT,
        DST_IP_ADDR,
        DST_UDP_PORT,
        SOCKET_TIMEOUT,
        MAX_PACKET_SIZE,
        MAX_DATA_SIZE,
    };

    const char* short_options = "?h";

    const struct option long_options[] = {
    {"help",no_argument,NULL,'h'},
    {"host_device_uid",required_argument,NULL,HOST_DEVICE_UID},
    {"host_ip_addr",required_argument,NULL,HOST_IP_ADDR},
    {"dst_ip_addr",required_argument,NULL,DST_IP_ADDR},
    {"host_udp_port",required_argument,NULL,HOST_UDP_PORT},
    {"dst_udp_port",required_argument,NULL,DST_UDP_PORT},
    {"socket_timeout",required_argument,NULL,SOCKET_TIMEOUT},
    {"max_packet_size",required_argument,NULL,MAX_PACKET_SIZE},
    {"max_data_size",required_argument,NULL,MAX_DATA_SIZE},
    {NULL,0,NULL,0}
    };

    int rez;
    int option_index;

    uint32_t host_device_uid = 1;
    char* host_ip_addr = "127.0.0.1";
    char* dst_ip_addr = "127.0.0.1";
    uint32_t host_udp_port = 50020;
    uint32_t dst_udp_port = 0;
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
                " --host_device_uid         Host device ID (\"1\" by default)\n"
                " --host_ip_addr            Host IP-addr (\"127.0.0.1\" by default)\n"
                " --dst_ip_addr             Destination IP-addr (\"127.0.0.1\" by default)\n"
                " --host_udp_port           Host UDP Port (\"50020\" by default)\n"
                " --dst_udp_port            Destination UDP Port (\"0\" by default)\n"
                " --socket_timeout          Socket waiting time for data [ms] (\"100\" ms by default)\n"
                " --max_packet_size         Maximum UDP packet size [bytes] (\"1024\" bytes by default)\n"
                " --max_data_size           Maximum protocol packet size [bytes] (\"1048576\" bytes by default)\n"
                "\n"
                "An example command line would look like this:\n"
                "---------------------------------------------\n"
                " TestReceiver --host_ip_addr 127.0.0.1 --host_udp_port 50020\n"
            );
            return NULL;
            break;
        };
        case HOST_DEVICE_UID: {
            sscanf(optarg, "%d", &host_device_uid);
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
        case HOST_UDP_PORT: {
            sscanf(optarg, "%d", &host_udp_port);
            break;
        };
        case DST_UDP_PORT: {
            sscanf(optarg, "%d", &dst_udp_port);
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
               "host_device_uid\t: %d\n"
               "host_ip_addr\t: %s\n"
               "dst_ip_addr\t: %s\n"
               "host_udp_port\t: %d\n"
               "dst_udp_port\t: %d\n"
               "socket_timeout\t: %d\n"
               "max_packet_size\t: %d\n"
               "max_data_size\t: %d\n\n",
               host_device_uid, host_ip_addr, dst_ip_addr, host_udp_port, dst_udp_port,
               socket_timeout, max_packet_size, max_data_size);
    }

    return generate_config_string(
                host_device_uid, host_ip_addr, dst_ip_addr,
                host_udp_port, dst_udp_port, socket_timeout,
                max_packet_size, max_data_size);

}

char* get_default_config()
{
    uint32_t host_device_uid = 1;
    char* host_ip_addr = "127.0.0.1";
    char* dst_ip_addr = "127.0.0.1";
    uint32_t host_udp_port = 50020;
    uint32_t dst_udp_port = 0;
    uint32_t socket_timeout = 100;
    uint32_t max_packet_size = 1024;
    uint32_t max_data_size = 1024 * 1024;

    printf("## DEFAULT SETTINGS ##\n\n"
           "host_device_uid\t: %d\n"
           "host_ip_addr\t: %s\n"
           "dst_ip_addr\t: %s\n"
           "host_udp_port\t: %d\n"
           "dst_udp_port\t: %d\n"
           "socket_timeout\t: %d\n"
           "max_packet_size\t: %d\n"
           "max_data_size\t: %d\n\n",
           host_device_uid, host_ip_addr, dst_ip_addr, host_udp_port, dst_udp_port,
           socket_timeout, max_packet_size, max_data_size);

    return generate_config_string(
                host_device_uid, host_ip_addr, dst_ip_addr,
                host_udp_port, dst_udp_port, socket_timeout,
                max_packet_size, max_data_size);
}

char* generate_config_string(
        uint32_t host_device_uid, char* host_ip_addr, char* dst_ip_addr,
        uint32_t host_udp_port, uint32_t dst_udp_port, uint32_t socket_timeout,
        uint32_t max_packet_size, uint32_t max_data_size)
{
    char* config = calloc(1024, sizeof (char));

    sprintf(config,
            "--host_device_uid %d "
            "--host_ip_addr %s "
            "--dst_ip_addr %s "
            "--host_udp_port %d "
            "--dst_udp_port %d "
            "--socket_timeout %d "
            "--max_packet_size %d "
            "--max_data_size %d",
            host_device_uid, host_ip_addr, dst_ip_addr, host_udp_port, dst_udp_port,
            socket_timeout, max_packet_size, max_data_size);

    return config;
}


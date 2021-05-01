#include "smartchannel.h"

#include <mpack/mpack.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

uint32_t answ_count = 0;
uint32_t sender_id = 2;
int8_t smart_short_data_callback(char* data, uint32_t data_size, uint32_t data_device_id, void* rqst_msg)
{
    answ_count++;
    printf("+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((smart_msg_t*)rqst_msg)->cmd_name, ((smart_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = SMART_PARSER_RETURN_STATUS_NO_DATA;

    if (data_device_id == sender_id)
    {
        smart_msg_t* msg = rqst_msg;
        typedef struct
        {
            char* received_data;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->received_data = calloc(data_size, sizeof (char));
        memcpy(((answer*)msg->result)->received_data, data, data_size);

        status = SMART_PARSER_RETURN_STATUS_DATA_READY;
    }
    return status;
}
int8_t smart_short_data_timeout_callback(void* rqst_msg)
{
    smart_msg_t* msg = rqst_msg;

    printf("- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
int8_t smart_short_data_free_result_callback(void* rqst_msg)
{
    smart_msg_t* msg = rqst_msg;

    printf("- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        typedef struct
        {
            char* received_data;
        }answer;

        free(((answer*)msg->result)->received_data);
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}



int main(int argc, char* argv[])
{

    printf("##############################\n");
    printf("#                            #\n");
    printf("#   Data Reseiver Test v2.0  #\n");
    printf("#                            #\n");
    printf("##############################\n\n");

    char* version = smart_channel_version();
    printf("Current smart-protocol version: %s\n", version);


    char config[1024] = {0};

    if (argc > 1)
    {
        printf("\n\n## CURRENT SETTINGS ##\n\n");
        for (int i = 1; i < argc; i+=2)
            printf("%s\t: %s\n", &argv[i][1], argv[i+1]);
        printf("\n");
        int len = 0;
        for (int i = 1; i < argc; i++)
        {
            int size = strlen(argv[i]);
            if (size > 0 && (len + size + 1 <= (int)sizeof (config)))
            {
                strncpy(&config[len], argv[i], size);
                len += strlen(argv[i]);
                strncpy(&config[len], " ", 1);
                len += 1;
            }
        }
    }else
    {
        uint32_t src_device_uid = 1;
        char* dst_ip_addr = "192.168.1.30";
        char* host_ip_addr = "192.168.1.2";
        uint32_t in_udp_port = 50021;
        uint32_t out_udp_port = 50021;
        uint32_t socket_timeout = 100;
        uint32_t max_packet_size = 65535;
        uint32_t max_data_size = 20000000;
        sprintf(config,
                "-src_device_uid %d "
                "-dst_ip_addr %s "
                "-host_ip_addr %s "
                "-in_udp_port %d "
                "-out_udp_port %d "
                "-socket_timeout %d "
                "-max_packet_size %d "
                "-max_data_size %d",
                src_device_uid, dst_ip_addr, host_ip_addr, in_udp_port, out_udp_port,
                socket_timeout, max_packet_size, max_data_size);

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
    }
    smart_channel channel;

    smart_channel_init(&channel, config);

    // Create test data answer.
    char* short_data = "HELLO, SHORT DATA TEST!";

    printf("Start recieving data...\n");

    clock_t start, end;
    start = clock();
    // Reading loop
    while (TRUE)
    {
        // Wait data from 0 logic port without time limit.
        smart_msg_t* msg = smart_channel_get_msg(&channel, 5000);
        if (msg != NULL)
        {
            // Calculate time between data.
            end = clock();
            double time_spent = (double)(end - start);

            // Print calculated bandwidth value.
            printf("Recieved %d bytes to %s during %lf ms\n", msg->data_size, msg->cmd_name, time_spent);
            start = clock();

            if (strcmp(msg->cmd_name, "SEND_SHORT_DATA_TEST") == 0)
            {
                // Create answ msg
                char* data                          = short_data;
                uint32_t data_size                  = strlen(short_data);
                char* data_type                     = "blob";
                uint8_t is_check_crc                = FALSE; //check crc disabled
                uint8_t is_confirmation             = FALSE; //confirmation disabled
                uint8_t is_one_answ                 = TRUE; //wait only one answer
                uint32_t waiting_time               = 1000; //ms
                smart_answ_callback answ_clb        = NULL;
                smart_timeout_callback timeout_clb  = smart_short_data_timeout_callback;
                smart_free_callback free_clb        = smart_short_data_free_result_callback;

                smart_msg_t* answ_msg = smart_create_answ_msg(msg, data, data_size, data_type,
                                                              is_check_crc, is_confirmation, is_one_answ,
                                                              waiting_time,
                                                              answ_clb, timeout_clb, free_clb);

                // Send answ msg
                if (!smart_channel_send_msg(&channel, answ_msg))
                    printf("No data has been sent.\n");
                else
                    printf("%d - Bytes was sent.\n", data_size);

                // Cleanup answ msg
                smart_cleanup_msg(answ_msg);
            }else if (strcmp(msg->cmd_name, "test_long_data") == 0)
            {

            }
        }
        // Cleanup rqst msg
        smart_cleanup_msg(msg);
    }

    return 0;
}

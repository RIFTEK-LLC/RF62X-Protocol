#include "RF62Xmsg.h"
#include <string.h>
#include <stdlib.h>

#include <time.h>

#include "RF62Xparser.h"
#include "RF62Xchannel.h"

#ifndef _WIN32
#define INVALID_SOCKET          (-1)
#define SOCKET_ERROR            (-1)
#define TRUE 1
#define FALSE 0
#endif

int msg_count = 0;
RF62X_msg_t *RF62X_create_rqst_msg(char *cmd_name, char *data, uint32_t data_size, char* data_type,
                                   uint8_t is_check_crc, uint8_t is_confirmation, uint8_t is_one_answ,
                                   uint32_t timeout,
                                   RF62X_answ_callback answ_clb,
                                   RF62X_timeout_callback timeout_clb,
                                   RF62X_free_callback free_clb)
{
    RF62X_msg_t* rqst_msg = calloc(1, sizeof (RF62X_msg_t));

    strcpy(rqst_msg->type, "rqst");
    strcpy(rqst_msg->cmd_name, cmd_name);
    strcpy(rqst_msg->container_type, data_type);

    rqst_msg->check_crc_flag = is_check_crc;
    rqst_msg->confirmation_flag = is_confirmation;
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
                                   uint32_t timeout,
                                   RF62X_answ_callback answ_clb,
                                   RF62X_timeout_callback timeout_clb,
                                   RF62X_free_callback free_clb)
{
    RF62X_msg_t* answ_msg = calloc(1, sizeof (RF62X_msg_t));

    strcpy(answ_msg->type, "answ");
    strcpy(answ_msg->cmd_name, rqst_msg->cmd_name);
    strcpy(answ_msg->container_type, data_type);

    answ_msg->check_crc_flag = is_check_crc;
    answ_msg->confirmation_flag = is_confirmation;
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

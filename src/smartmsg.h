#ifndef SMARTMSG_H
#define SMARTMSG_H

#include <stddef.h>
#include <stdint.h>

typedef int8_t (*smart_answ_callback)(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg);
typedef int8_t (*smart_timeout_callback)(void* rqst_msg);
typedef int8_t (*smart_free_callback)(void* rqst_msg);

typedef struct
{
    char type[64];
    char cmd_name[256];
    char container_type[64];

    uint8_t check_crc_flag;
    uint8_t confirmation_flag;
    uint8_t one_answ_flag;
    uint8_t wait_answ_flag;

    char* data;
    uint32_t data_size;

    smart_answ_callback _answ_clb;
    smart_timeout_callback _timeout_clb;
    smart_free_callback _free_clb;

    uint64_t _msg_uid;
    uint64_t _device_id;
    uint64_t _uid;
    uint32_t _sending_time;
    uint32_t _timeout;

    uint16_t state;            ///< Data receiver acknowledgment flag

    void* result;
}smart_msg_t;


#endif // SMARTMSG_H

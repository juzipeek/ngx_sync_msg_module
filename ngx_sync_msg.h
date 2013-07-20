#ifndef _NGX_SYNC_MSG_H_INCLUDE_
#define _NGX_SYNC_MSG_H_INCLUDE_


#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                            shm_name;
    ngx_uint_t                           shm_size;
    ngx_msec_t                           read_msg_timeout;
} ngx_sync_msg_main_conf_t;


typedef struct ngx_sync_msg_status_s {
    ngx_pid_t                            pid;
    ngx_msec_t                           time;
} ngx_sync_msg_status_t;


typedef struct ngx_sync_msg_shctx_s {
    ngx_queue_t                          msg_queue;
    ngx_uint_t                           version;
    ngx_sync_msg_status_t               *status;
} ngx_sync_msg_shctx_t;


typedef struct ngx_sync_msg_global_ctx_s {
    ngx_event_t                          msg_timer;
    ngx_slab_pool_t                     *shpool;
    ngx_sync_msg_shctx_t                *sh;
} ngx_sync_msg_global_ctx_t;


typedef struct ngx_sync_msg_s {
    ngx_queue_t                          queue;
    ngx_str_t                            title;
    ngx_str_t                            content;
    ngx_int_t                            count;
    ngx_pid_t                           *pid;
} ngx_sync_msg_t;


ngx_int_t ngx_sync_msg_send(ngx_str_t *title, ngx_buf_t *body);


extern ngx_flag_t ngx_sync_msg_enable;


#endif

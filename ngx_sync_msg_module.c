#include <ngx_sync_msg.h>


#define NGX_SYNC_MSG_SHM_NAME_LEN  256
#define ngx_sync_msg_add_timer(ev, timeout)                     \
    if (!ngx_exiting && !ngx_quit) ngx_add_timer(ev, (timeout))


static void *ngx_sync_msg_create_main_conf(ngx_conf_t *cf);
static char *ngx_sync_msg_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_sync_msg_init_process(ngx_cycle_t *cycle);
static void ngx_sync_msg_exit_process(ngx_cycle_t *cycle);
static char *ngx_sync_msg_init_shm(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_sync_msg_get_shm_name(ngx_str_t *shm_name,
    ngx_pool_t *pool, ngx_uint_t generation);
static ngx_int_t ngx_sync_msg_init_shm_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static void ngx_sync_msg_read_msg(ngx_event_t *ev);
static void ngx_sync_msg_purge_msg(ngx_pid_t opid, ngx_pid_t npid);
static void ngx_sync_msg_read_msg_locked(ngx_event_t *ev);
static void ngx_sync_msg_destroy_msg(ngx_slab_pool_t *shpool,
    ngx_sync_msg_t *msg);
static ngx_int_t ngx_sync_msg_dummy_read_filter(ngx_pool_t *pool,
    ngx_str_t *title, ngx_str_t *content, ngx_uint_t index);
static ngx_int_t ngx_sync_msg_dummy_crashed_filter(ngx_pid_t opid,
    ngx_pid_t npid);


ngx_int_t (*ngx_sync_msg_top_read_filter) (ngx_pool_t *pool, ngx_str_t *title,
    ngx_str_t *content, ngx_uint_t index);
ngx_int_t (*ngx_sync_msg_top_crashed_filter) (ngx_pid_t opid, ngx_pid_t npid);


static ngx_command_t  ngx_sync_msg_commands[] = {

    { ngx_string("sync_msg_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_sync_msg_main_conf_t, read_msg_timeout),
      NULL },

    { ngx_string("sync_msg_shm_zone_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_sync_msg_main_conf_t, shm_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_sync_msg_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

    ngx_sync_msg_create_main_conf,  /* create main configuration */
    ngx_sync_msg_init_main_conf,    /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    NULL,                           /* create location configuration */
    NULL                            /* merge location configuration */
};


ngx_module_t  ngx_sync_msg_module = {
    NGX_MODULE_V1,
    &ngx_sync_msg_module_ctx,       /* module context */
    ngx_sync_msg_commands,          /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    ngx_sync_msg_init_process,      /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    ngx_sync_msg_exit_process,      /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_flag_t ngx_sync_msg_enable = 0;  /* set to 1 in other modules */
static ngx_uint_t ngx_sync_msg_shm_generation = 0;
static ngx_sync_msg_global_ctx_t ngx_sync_msg_global_ctx;


static void *
ngx_sync_msg_create_main_conf(ngx_conf_t *cf)
{
    ngx_sync_msg_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_sync_msg_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->shm_size = NGX_CONF_UNSET_UINT;
    conf->read_msg_timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}


static char *
ngx_sync_msg_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_sync_msg_main_conf_t  *smcf = conf;

    if (!ngx_sync_msg_enable) {
        return NGX_CONF_OK;
    }

    ngx_sync_msg_top_read_filter = ngx_sync_msg_dummy_read_filter;
    ngx_sync_msg_top_crashed_filter = ngx_sync_msg_dummy_crashed_filter;

    if (smcf->shm_size == NGX_CONF_UNSET_UINT) {
        smcf->shm_size = 2 * 1024 * 1024;
    }

    if (smcf->read_msg_timeout == NGX_CONF_UNSET_MSEC) {
        smcf->read_msg_timeout = 1000;
    }

    return ngx_sync_msg_init_shm(cf, conf);
}


static char *
ngx_sync_msg_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_sync_msg_main_conf_t *smcf = conf;

    ngx_shm_zone_t  *shm_zone;

    ngx_sync_msg_shm_generation++;

    if (ngx_sync_msg_get_shm_name(&smcf->shm_name, cf->pool,
                                     ngx_sync_msg_shm_generation)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &smcf->shm_name, smcf->shm_size,
                                     &ngx_sync_msg_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->data = cf->pool;
    shm_zone->init = ngx_sync_msg_init_shm_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_sync_msg_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool,
    ngx_uint_t generation)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, NGX_SYNC_MSG_SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, NGX_SYNC_MSG_SHM_NAME_LEN, "%s#%ui",
                        "ngx_sync_msg_module", generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_sync_msg_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t    *shpool;
    ngx_sync_msg_shctx_t  *sh;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    sh = ngx_slab_alloc(shpool, sizeof(ngx_sync_msg_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    ngx_sync_msg_global_ctx.sh = sh;
    ngx_sync_msg_global_ctx.shpool = shpool;

    ngx_queue_init(&sh->msg_queue);

    sh->version = 0;
    sh->status = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_sync_msg_init_process(ngx_cycle_t *cycle)
{
    ngx_int_t                    i, rc;
    ngx_pid_t                    pid;
    ngx_time_t                  *tp;
    ngx_msec_t                   now;
    ngx_event_t                 *timer;
    ngx_core_conf_t             *ccf;
    ngx_slab_pool_t             *shpool;
    ngx_sync_msg_shctx_t        *sh;
    ngx_sync_msg_status_t       *status;
    ngx_sync_msg_main_conf_t    *smcf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    smcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_sync_msg_module);

    if (!smcf || !ngx_sync_msg_enable) {
        return NGX_OK;
    }

    timer = &ngx_sync_msg_global_ctx.msg_timer;
    ngx_memzero(timer, sizeof(ngx_event_t));

    timer->handler = ngx_sync_msg_read_msg;
    timer->log = cycle->log;
    timer->data = smcf;

    ngx_add_timer(timer, smcf->read_msg_timeout);

    shpool = ngx_sync_msg_global_ctx.shpool;
    sh = ngx_sync_msg_global_ctx.sh;

    ngx_shmtx_lock(&shpool->mutex);

    if (sh->status == NULL) {
        sh->status = ngx_slab_alloc_locked(shpool,
                         sizeof(ngx_sync_msg_status_t) * ccf->worker_processes);

        if (sh->status == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        ngx_memzero(sh->status, sizeof(ngx_msec_t) * ccf->worker_processes);

        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    if (sh->version != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "[sync_msg] process start after abnormal exits");

        ngx_msleep(smcf->read_msg_timeout * 2);

        ngx_time_update();
        tp = ngx_timeofday();
        now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

        ngx_shmtx_lock(&shpool->mutex);

        if (sh->status == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_OK;
        }

        status = &sh->status[0];

        for (i = 1; i < ccf->worker_processes; i++) {

            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "[sync_msg] process %P %ui %ui",
                          sh->status[i].pid, status->time, sh->status[i].time);

            if (status->time > sh->status[i].time) {
                status = &sh->status[i];
            }
        }

        pid = status->pid;
        status->time = now;
        status->pid = ngx_pid;

        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "[sync_msg] new process is %P, old process is %P",
                      ngx_pid, pid);

        ngx_sync_msg_purge_msg(pid, ngx_pid);

        ngx_shmtx_unlock(&shpool->mutex);

        rc = ngx_sync_msg_top_crashed_filter(pid, ngx_pid);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "[sync_msg] crashed filter rc: [%i]", rc);
        }
    }

    return NGX_OK;
}


static void
ngx_sync_msg_exit_process(ngx_cycle_t *cycle)
{

}


static void
ngx_sync_msg_read_msg(ngx_event_t *ev)
{
    ngx_slab_pool_t           *shpool;
    ngx_sync_msg_main_conf_t  *smcf;

    smcf = ev->data;
    shpool = ngx_sync_msg_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);

    ngx_sync_msg_read_msg_locked(ev);

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_sync_msg_add_timer(ev, smcf->read_msg_timeout);
}


static void
ngx_sync_msg_read_msg_locked(ngx_event_t *ev)
{
    ngx_int_t               i, rc;
    ngx_str_t               title, content;
    ngx_flag_t              found;
    ngx_time_t             *tp;
    ngx_pool_t             *pool;
    ngx_msec_t              now;
    ngx_queue_t            *q, *t;
    ngx_sync_msg_t         *msg;
    ngx_core_conf_t        *ccf;
    ngx_slab_pool_t        *shpool;
    ngx_sync_msg_shctx_t   *sh;
    ngx_sync_msg_status_t  *status;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "[sync_msg] read msg %P", ngx_pid);

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    sh = ngx_sync_msg_global_ctx.sh;
    shpool = ngx_sync_msg_global_ctx.shpool;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    for (i = 0; i < ccf->worker_processes; i++) {
        status = &sh->status[i];

        if (status->pid == 0 || status->pid == ngx_pid) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "[sync_msg] process %P update time %ui",
                           status->pid, status->time);

            status->pid = ngx_pid;
            status->time = now;
            break;
        }
    }

    if (ngx_queue_empty(&sh->msg_queue)) {
        return;
    }

    pool = ngx_create_pool(ngx_pagesize, ev->log);
    if (pool == NULL) {
        return;
    }

    for (q = ngx_queue_last(&sh->msg_queue);
         q != ngx_queue_sentinel(&sh->msg_queue);
         q = ngx_queue_prev(q))
    {
        msg = ngx_queue_data(q, ngx_sync_msg_t, queue);

        if (msg->count == ccf->worker_processes) {
            t = ngx_queue_next(q); ngx_queue_remove(q); q = t;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                                  "[sync_msg] destroy msg %V:%V",
                                  &msg->title, &msg->content);

            ngx_sync_msg_destroy_msg(shpool, msg);
            continue;
        }

        found = 0;
        for (i = 0; i < msg->count; i++) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "[sync_msg] msg pids [%P]", msg->pid[i]);

            if (msg->pid[i] == ngx_pid) {
                found = 1;
                break;
            }
        }

        if (found) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "[sync_msg] msg %V count %ui found",
                           &msg->title, msg->count);
            continue;
        }

        msg->pid[i] = ngx_pid;
        msg->count++;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                       "[sync_msg] msg %V count %ui", &msg->title, msg->count);

        title = msg->title;
        content = msg->content;

        rc = ngx_sync_msg_top_read_filter(pool, &title, &content,
                                          msg->module_index);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "[sync_msg] read msg error, may cause the "
                          "config inaccuracy, title:%V, content:%V",
                          &title, &content);
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "[sync_msg] read end");

    ngx_destroy_pool(pool);

    return;
}


ngx_int_t
ngx_sync_msg_send_module_index(ngx_str_t *title, ngx_buf_t *content,
    ngx_uint_t index)
{
    ngx_int_t         rc;
    ngx_slab_pool_t  *shpool;

    shpool = ngx_sync_msg_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);

    rc = ngx_sync_msg_send_locked_module_index(title, content, index);

    ngx_shmtx_unlock(&shpool->mutex);

    return rc;
}


ngx_int_t
ngx_sync_msg_send_locked_module_index(ngx_str_t *title, ngx_buf_t *content,
    ngx_uint_t index)
{
    ngx_sync_msg_t        *msg;
    ngx_core_conf_t       *ccf;
    ngx_slab_pool_t       *shpool;
    ngx_sync_msg_shctx_t  *sh;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    sh = ngx_sync_msg_global_ctx.sh;
    shpool = ngx_sync_msg_global_ctx.shpool;

    msg = ngx_slab_alloc_locked(shpool, sizeof(ngx_sync_msg_t));
    if (msg == NULL) {
        goto failed;
    }

    ngx_memzero(msg, sizeof(ngx_sync_msg_t));

    msg->count = 0;
    msg->pid = ngx_slab_alloc_locked(shpool,
                                     sizeof(ngx_pid_t) * ccf->worker_processes);

    if (msg->pid == NULL) {
        goto failed;
    }

    ngx_memzero(msg->pid, sizeof(ngx_pid_t) * ccf->worker_processes);
    msg->pid[0] = ngx_pid;
    msg->count++;
    msg->module_index = index;

    msg->title.data = ngx_slab_alloc_locked(shpool, title->len);
    if (msg->title.data == NULL) {
        goto failed;
    }

    ngx_memcpy(msg->title.data, title->data, title->len);
    msg->title.len = title->len;

    if (content) {
        msg->content.data = ngx_slab_alloc_locked(shpool,
                                                  content->last - content->pos);
        if (msg->content.data == NULL) {
            goto failed;
        }

        ngx_memcpy(msg->content.data, content->pos,
                   content->last - content->pos);

        msg->content.len = content->last - content->pos;

    } else {
        msg->content.data = NULL;
        msg->content.len = 0;
    }

    sh->version++;

    if (sh->version == 0) {
        sh->version = 1;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[sync_msg] send msg %V count %ui version: %ui",
                   &msg->title, msg->count, sh->version);

    ngx_queue_insert_head(&sh->msg_queue, &msg->queue);

    return NGX_OK;

failed:

    if (msg) {
        ngx_sync_msg_destroy_msg(shpool, msg);
    }

    return NGX_ERROR;
}


static void
ngx_sync_msg_destroy_msg(ngx_slab_pool_t *shpool, ngx_sync_msg_t *msg)
{
    if (msg->pid) {
        ngx_slab_free_locked(shpool, msg->pid);
    }

    if (msg->title.data) {
        ngx_slab_free_locked(shpool, msg->title.data);
    }

    if (msg->content.data) {
        ngx_slab_free_locked(shpool, msg->content.data);
    }

    ngx_slab_free_locked(shpool, msg);
}


static void
ngx_sync_msg_purge_msg(ngx_pid_t opid, ngx_pid_t npid)
{
    ngx_int_t               i;
    ngx_queue_t            *q;
    ngx_sync_msg_t         *msg;
    ngx_sync_msg_shctx_t   *sh;

    sh = ngx_sync_msg_global_ctx.sh;

    for (q = ngx_queue_last(&sh->msg_queue);
         q != ngx_queue_sentinel(&sh->msg_queue);
         q = ngx_queue_prev(q))
    {
        msg = ngx_queue_data(q, ngx_sync_msg_t, queue);

        for (i = 0; i < msg->count; i++) {
            if (msg->pid[i] == opid) {

                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                              "[sync_msg] restore one pid conflict"
                              " old: %P, new: %P", opid, npid);
                msg->pid[i] = npid;
            }
        }
    }
}


static ngx_int_t
ngx_sync_msg_dummy_read_filter(ngx_pool_t *pool, ngx_str_t *title,
    ngx_str_t *content, ngx_uint_t index)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[sync_msg] dummy read filter, module index: [%ui]", index);

    return NGX_OK;
}


static ngx_int_t
ngx_sync_msg_dummy_crashed_filter(ngx_pid_t opid, ngx_pid_t npid)
{
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[sync_msg] dummy crashed filter, "
                   "old pid: [%ui], new pid: [%ui]", opid, npid);

    return NGX_OK;
}

#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>


#define NGX_SYNC_MSG_SHM_NAME_LEN 256


typedef struct {
    ngx_str_t                            shm_name;
    ngx_uint_t                           shm_size;
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
    ngx_uint_t                           flag;
    ngx_pid_t                           *pid;
} ngx_sync_msg_t;


static void *ngx_sync_msg_create_main_conf(ngx_conf_t *cf);
static char *ngx_sync_msg_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_sync_msg_init_process(ngx_cycle_t *cycle);
static void ngx_sync_msg_exit_process(ngx_cycle_t *cycle);
static char *ngx_sync_msg_init_shm(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_sync_msg_get_shm_name(ngx_str_t *shm_name,
    ngx_pool_t *pool, ngx_uint_t generation);
static ngx_int_t ngx_sync_msg_init_shm_zone(ngx_shm_zone_t *shm_zone,
    void *data);


static ngx_command_t  ngx_sync_msg_commands[] = {
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
    &ngx_sync_msg_module_ctx,    /* module context */
    ngx_sync_msg_commands,       /* module directives */
    NGX_CORE_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,                        /* init module */
    ngx_sync_msg_init_process,   /* init process */
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    ngx_sync_msg_exit_process,   /* exit process */
    NULL,                        /* exit master */
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

    return conf;
}


static char *
ngx_sync_msg_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_sync_msg_main_conf_t  *smcf = conf;

    if (!ngx_sync_msg_enable) {
        return NGX_CONF_OK;
    }

    if (smcf->shm_size == NGX_CONF_UNSET_UINT) {
        smcf->shm_size = 2 * 1024 * 1024;
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
    return NGX_OK;
}


static void
ngx_sync_msg_exit_process(ngx_cycle_t *cycle)
{

}

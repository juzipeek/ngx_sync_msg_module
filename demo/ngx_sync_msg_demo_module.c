#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_sync_msg.h>


static char *ngx_sync_msg_demo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_sync_msg_demo_pre_config(ngx_conf_t *cf);
static ngx_int_t ngx_sync_msg_read_demo_filter(ngx_pool_t *pool,
    ngx_str_t *title, ngx_str_t *content, ngx_uint_t index);


static ngx_command_t ngx_sync_msg_demo_commands[] = {

    { ngx_string("sync_msg_demo"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_sync_msg_demo,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_sync_msg_demo_module_ctx = {
    ngx_sync_msg_demo_pre_config,  /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t ngx_sync_msg_demo_module = {
    NGX_MODULE_V1,
    &ngx_sync_msg_demo_module_ctx, /* module context */
    ngx_sync_msg_demo_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t ngx_sync_msg_demo_str = ngx_string("sync_msg_demo");
static ngx_sync_msg_read_filter_pt ngx_sync_msg_next_read_filter;
static ngx_pool_t *ngx_sync_msg_demo_pool = NULL;


static ngx_int_t
ngx_sync_msg_demo_pre_config(ngx_conf_t *cf)
{
    ngx_sync_msg_enable = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_sync_msg_demo_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = ngx_sync_msg_demo_str.len;

        return ngx_http_send_header(r);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "sync msg demo uri: %V", &r->uri);

    if (r->uri.len != 1) {

        if (ngx_sync_msg_demo_pool) {
            ngx_destroy_pool(ngx_sync_msg_demo_pool);
        }

        ngx_sync_msg_demo_pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
        if (ngx_sync_msg_demo_pool == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_sync_msg_demo_str.data = ngx_pstrdup(ngx_sync_msg_demo_pool,
                                                 &r->uri);
        ngx_sync_msg_demo_str.len = r->uri.len;

        ngx_sync_msg_send(&ngx_sync_msg_demo_str, NULL,
                          ngx_sync_msg_demo_module);
    }

    out.buf = b;
    out.next = NULL;

    b->pos = ngx_sync_msg_demo_str.data;
    b->last = ngx_sync_msg_demo_str.data + ngx_sync_msg_demo_str.len;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_sync_msg_demo_str.len;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_sync_msg_demo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_sync_msg_demo_handler;

    ngx_sync_msg_next_read_filter = ngx_sync_msg_top_read_filter;
    ngx_sync_msg_top_read_filter = ngx_sync_msg_read_demo_filter;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_sync_msg_read_demo_filter(ngx_pool_t *pool, ngx_str_t *title,
    ngx_str_t *content, ngx_uint_t index)
{
    if (index != ngx_sync_msg_demo_module.index) {
        return ngx_sync_msg_next_read_filter(pool, title, content, index);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                   "sync msg demo title: %V", title);

    if (ngx_sync_msg_demo_pool) {
        ngx_destroy_pool(ngx_sync_msg_demo_pool);
    }

    ngx_sync_msg_demo_pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (ngx_sync_msg_demo_pool == NULL) {
        return NGX_ERROR;
    }

    ngx_sync_msg_demo_str.data = ngx_pstrdup(ngx_sync_msg_demo_pool,
                                             title);
    ngx_sync_msg_demo_str.len = title->len;

    return ngx_sync_msg_next_read_filter(pool, title, content, index);
}

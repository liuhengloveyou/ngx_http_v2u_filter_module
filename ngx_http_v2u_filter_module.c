#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define BUF_SIZE 32768

typedef struct {
	ngx_flag_t                enable;
} ngx_http_v2u_filter_conf_t;

typedef struct {
	ngx_buf_t           *tmp_buf;
	ngx_chain_t         *free;
	ngx_chain_t         *busy;
} ngx_http_v2u_filter_ctx_t;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

ngx_module_t  ngx_http_v2u_filter_module;


static int conv2u(const char* source, int slen, char* desc, int dlen)
{
	if (!source || !desc) {
		return -1;
	}

	if (!setlocale(LC_CTYPE, "zh_CN.UTF-8")) {
		return -1;
	}

	mbstate_t mbst = {0};
	wchar_t* lpWC = (wchar_t *)malloc(slen * sizeof(wchar_t) + 10);
	if (!lpWC) {
		return -1;
	}
	memset((char*)lpWC, 0, slen * sizeof(wchar_t) + 10);

	int rt = mbsrtowcs(lpWC, (const char**)&source, slen, &mbst);
	if (rt == -1) {
		free(lpWC);
		return -1;
	}

	int i = 0;
	int idx = 0;
	int tmplen = wcslen(lpWC);
	for (i = 0; i < tmplen; i++) {
		char c[5] = {0};
		snprintf(c, 5, "%x", lpWC[i]);
		if (strlen(c) == 4){
			idx += snprintf(desc+idx, dlen - idx, "\\u%s", c);
		} else if (strlen(c) == 3) {
			idx += snprintf(desc+idx, dlen - idx, "\\u0%s", c);
		} else {
			unsigned char d = 0;
			memcpy((char*)&d, (char*)(&lpWC[i]), 1);
			if (d > 127) {
				idx += snprintf(desc+idx, dlen - idx, "\\u00%s", c);
			} else {
				idx += snprintf(desc+idx, dlen - idx, "%c", lpWC[i]);
			}
		}
	}

	free(lpWC);
	return idx;
}

static ngx_int_t ngx_http_v2u_header_filter(ngx_http_request_t *r)
{
	ngx_http_v2u_filter_conf_t *conf;
	ngx_http_v2u_filter_ctx_t *ctx;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_v2u_filter_module);

	if (conf->enable == 0
	    || r != r->main
	    || (r->method & NGX_HTTP_HEAD)
	    || r->headers_out.status != NGX_HTTP_OK
	    || r->headers_out.status == NGX_HTTP_NOT_MODIFIED
	    || r->headers_out.status == NGX_HTTP_NO_CONTENT
	    || r->header_only)
	{
		return ngx_http_next_header_filter(r);
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_v2u_filter_module);
	if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_v2u_filter_ctx_t));
		if (ctx == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "pcalloc v2u_ctx error");
			return NGX_ERROR;
		}

		ctx->tmp_buf = ngx_create_temp_buf(r->pool, BUF_SIZE);
		if (ctx->tmp_buf == NULL) {
			return NGX_ERROR;
		}

		ctx->tmp_buf->tag = (ngx_buf_tag_t) &ngx_http_v2u_filter_module;
		ctx->tmp_buf->recycled = 1;

		ngx_http_set_ctx(r, ctx, ngx_http_v2u_filter_module);
	}

	r->filter_need_in_memory = 1;

	return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_v2u_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_http_v2u_filter_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_v2u_filter_module);
	if (conf->enable == 0 || in == NULL || r->header_only) {
		return ngx_http_next_body_filter(r, in);
	}

	ngx_http_v2u_filter_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_v2u_filter_module);
	if (ctx == NULL) {
		return ngx_http_next_body_filter(r, in);
	}

	ngx_chain_t *out = NULL;
	ngx_chain_t **ll = &out;
	ngx_chain_t *cl = in;

	for ( ; ; ) {
		off_t size = ngx_buf_size(cl->buf);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http v2u: %d", size);
		if (size <= 0) {
			return ngx_http_next_body_filter(r, in);
		}

		ngx_chain_t *tl = ngx_chain_get_free_buf(r->pool, &ctx->free);
		if (tl == NULL) {
			return NGX_ERROR;
		}

		ngx_buf_t *b = tl->buf;
		u_char *bs = b->start;
		if (bs == NULL) {
			bs = ngx_palloc(r->pool, BUF_SIZE);
			if (bs == NULL) {
				return NGX_ERROR;
			}

			b->start = bs;
			b->end = bs + BUF_SIZE -1;
			b->pos = bs;
			b->last = bs;
			b->temporary = 1;
			b->tag = (ngx_buf_tag_t) &ngx_http_v2u_filter_module;
		}

		int idx = conv2u((const char*)cl->buf->pos, size, (char *)bs, BUF_SIZE-1);
		b->last += idx - 1;
		
		*ll = tl;
		ll = &tl->next;

		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "pcalloc v2u_ctx error %s", out->buf->start);
		
		if (cl->next == NULL) {
			break;
		}
		cl = cl->next;
	}

	
	ngx_int_t rc = ngx_http_next_body_filter(r, out);

	ngx_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out, (ngx_buf_tag_t) &ngx_http_v2u_filter_module);

	return rc;
}


static char *ngx_http_v2u_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_v2u_filter_conf_t *prev = parent;
	ngx_http_v2u_filter_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);

	return NGX_CONF_OK;
}

static void *ngx_http_v2u_filter_create_conf(ngx_conf_t *cf)
{
	ngx_http_v2u_filter_conf_t *conf = (ngx_http_v2u_filter_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_v2u_filter_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->enable = NGX_CONF_UNSET;

	return conf;
}

static ngx_int_t ngx_http_v2u_filter_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_v2u_header_filter;

	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_v2u_body_filter;

	return NGX_OK;
}

static ngx_command_t  ngx_http_v2u_commands[] = {
	{ ngx_string("v2u_body"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_v2u_filter_conf_t, enable),
	  NULL },

	ngx_null_command
};

static ngx_http_module_t ngx_http_v2u_filter_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_v2u_filter_init,              /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_v2u_filter_create_conf,       /* create location configuration */
	ngx_http_v2u_filter_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_v2u_filter_module = {
	NGX_MODULE_V1,
	&ngx_http_v2u_filter_module_ctx,       /* module context */
	ngx_http_v2u_commands,                 /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

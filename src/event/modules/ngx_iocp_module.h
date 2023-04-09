
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_IOCP_MODULE_H_INCLUDED_
#define _NGX_IOCP_MODULE_H_INCLUDED_


typedef struct {
	ngx_uint_t  threads;
	ngx_uint_t  post_acceptex;
	ngx_flag_t  acceptex_read;
} ngx_iocp_conf_t;


extern ngx_module_t  ngx_iocp_module;


#endif /* _NGX_IOCP_MODULE_H_INCLUDED_ */

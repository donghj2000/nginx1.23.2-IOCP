
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_WSABUFS  64


ssize_t
ngx_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain, off_t limit)
{
    int           rc;
    u_char       *prev;
    u_long        bytes, flags;
    size_t        n, size;
    ngx_err_t     err;
    ngx_array_t   vec;
    ngx_event_t  *rev;
    LPWSABUF      wsabuf;
    WSABUF        wsabufs[NGX_WSABUFS];

    prev = NULL;
    wsabuf = NULL;
    flags = 0;
    size = 0;
    bytes = 0;

    vec.elts = wsabufs;
    vec.nelts = 0;
    vec.size = sizeof(WSABUF);
    vec.nalloc = NGX_WSABUFS;
    vec.pool = c->pool;

    /* coalesce the neighbouring bufs */

    while (chain) {
        n = chain->buf->end - chain->buf->last;

        if (limit) {
            if (size >= (size_t) limit) {
                break;
            }

            if (size + n > (size_t) limit) {
                n = (size_t) limit - size;
            }
        }

        if (prev == chain->buf->last) {
            wsabuf->len += n;

        } else {
            if (vec.nelts == vec.nalloc) {
                break;
            }

            wsabuf = ngx_array_push(&vec);
            if (wsabuf == NULL) {
                return NGX_ERROR;
            }

            wsabuf->buf = (char *) chain->buf->last;
            wsabuf->len = n;
        }

        size += n;
        prev = chain->buf->end;
        chain = chain->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "WSARecv: %d:%d", vec.nelts, wsabuf->len);


    rc = WSARecv(c->fd, vec.elts, vec.nelts, &bytes, &flags, NULL, NULL);

    rev = c->read;

    if (rc == -1) {
        rev->ready = 0;
        err = ngx_socket_errno;

        if (err == WSAEWOULDBLOCK) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "WSARecv() not ready");
            return NGX_AGAIN;
        }

        rev->error = 1;
        ngx_connection_error(c, err, "WSARecv() failed");
        return NGX_ERROR;
    }

#if (NGX_HAVE_FIONREAD)

    if (rev->available >= 0 && bytes > 0) {
        rev->available -= bytes;

        /*
         * negative rev->available means some additional bytes
         * were received between kernel notification and WSARecv(),
         * and therefore ev->ready can be safely reset even for
         * edge-triggered event methods
         */

        if (rev->available < 0) {
            rev->available = 0;
            rev->ready = 0;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "WSARecv: avail:%d", rev->available);

    } else if (bytes == size) {

        if (ngx_socket_nread(c->fd, &rev->available) == -1) {
            rev->error = 1;
            ngx_connection_error(c, ngx_socket_errno,
                                 ngx_socket_nread_n " failed");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "WSARecv: avail:%d", rev->available);
    }

#endif

    if (bytes < size) {
        rev->ready = 0;
    }

    if (bytes == 0) {
        rev->eof = 1;
    }

    return bytes;
}


ssize_t
ngx_overlapped_wsarecv_chain(ngx_connection_t *c, ngx_chain_t *chain, off_t limit)
{
	int           rc;
	u_char       *prev;
	u_long        bytes, flags;
	size_t        n, size;
	ngx_err_t     err;
	ngx_array_t   vec;
	ngx_event_t  *rev;
	LPWSAOVERLAPPED   ovlp;
	LPWSABUF      wsabuf;
	WSABUF        wsabufs[NGX_WSABUFS];

	prev = NULL;
	wsabuf = NULL;
	flags = 0;
	size = 0;
	bytes = 0;

	vec.elts = wsabufs;
	vec.nelts = 0;
	vec.size = sizeof(WSABUF);
	vec.nalloc = NGX_WSABUFS;
	vec.pool = c->pool;

	rev = c->read;
	/* coalesce the neighbouring bufs */
	if (!rev->ready) {
		ngx_log_error(NGX_LOG_ALERT, c->log, 0, "second wsa post");
		return NGX_AGAIN;
	}

	if (rev->complete) {
		rev->complete = 0;

		if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
			if (rev->ovlp.error) {
				ngx_connection_error(c, rev->ovlp.error, "WSARecv() failed");
				return NGX_ERROR;
			}

			ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"WSARecv ovlp: fd:%d %ul of %z",
				c->fd, rev->available, size);

			return rev->available;
		}

		if (WSAGetOverlappedResult(c->fd, (LPWSAOVERLAPPED)&rev->ovlp,
			&bytes, 0, NULL)
			== 0)
		{
			ngx_connection_error(c, ngx_socket_errno,
				"WSARecv() or WSAGetOverlappedResult() failed");
			return NGX_ERROR;
		}

		ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"WSARecv: fd:%d %ul of %z", c->fd, bytes, size);

		return bytes;
	}

	while (chain) {
		n = chain->buf->end - chain->buf->last;

		if (limit) {
			if (size >= (size_t)limit) {
				break;
			}

			if (size + n > (size_t)limit) {
				n = (size_t)limit - size;
			}
		}

		if (prev == chain->buf->last) {
			wsabuf->len += n;
		}
		else {
			if (vec.nelts == vec.nalloc) {
				break;
			}

			wsabuf = ngx_array_push(&vec);
			if (wsabuf == NULL) {
				return NGX_ERROR;
			}

			wsabuf->buf = (char *)chain->buf->last;
			wsabuf->len = n;
		}

		size += n;
		prev = chain->buf->end;
		chain = chain->next;
	}

	ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
		"WSARecv: %d:%d", vec.nelts, wsabuf->len);

	ovlp = (LPWSAOVERLAPPED)&c->read->ovlp;
	ngx_memzero(ovlp, sizeof(WSAOVERLAPPED));
	c->read->ovlp.error = 0;
	c->read->ovlp.opp_type = NGX_IOCP_IO;
	rc = WSARecv(c->fd, vec.elts, vec.nelts, &bytes, &flags, ovlp, NULL);
	rev->complete = 0;

	if (rc == -1) {
		err = ngx_socket_errno;
        rev->ready = 0;
		if (err == WSA_IO_PENDING || err == 0) {
			rev->active = 1;
			ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
				"WSARecv() posted");
			return NGX_AGAIN;
		}

		n = ngx_connection_error(c, err, "WSARecv() failed");

		if (n == NGX_ERROR) {
			rev->error = 1;
		}

		return n;
	}
	
	if (ngx_event_flags & NGX_USE_IOCP_EVENT) {

		/*
		* if a socket was bound with I/O completion port
		* then GetQueuedCompletionStatus() would anyway return its status
		* despite that WSARecv() was already complete
		*/
		rev->ready = 0;
		rev->active = 1;
		return NGX_AGAIN;
	}

	if (bytes == 0) {
		rev->eof = 1;
		rev->ready = 0;
	}
	else {
		rev->ready = 1;
	}

	rev->active = 0;

	return bytes;
}

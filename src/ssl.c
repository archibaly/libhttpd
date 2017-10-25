#include "config.h"

#ifdef HAVE_OPENSSL_SSL_H
#  include <openssl/ssl.h>
#endif
#ifdef HAVE_OPENSSL_ERR_H
#  include <openssl/err.h>
#endif

#if defined(HAVE_LIBSSL) && defined(HAVE_LIBCRYPTO)
SSL_CTX *_httpd_ssl_open(key, crt)
	const char	*key;
	const char	*crt;
{
	SSL_CTX *c;
	int rv;

	SSL_load_error_strings();
	SSL_library_init();

	if ((c = SSL_CTX_new(SSLv23_server_method())) != NULL)
		SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
	else
		goto err;

	if ((rv = SSL_CTX_use_PrivateKey_file(c, key, SSL_FILETYPE_PEM)) < 1)
	{
		if ((rv = SSL_CTX_use_PrivateKey_file(c, key, SSL_FILETYPE_ASN1)) < 1)
			goto err;
	}

	if ((rv = SSL_CTX_use_certificate_file(c, crt, SSL_FILETYPE_PEM)) < 1)
	{
		if ((rv = SSL_CTX_use_certificate_file(c, crt, SSL_FILETYPE_ASN1)) < 1)
			goto err;
	}

	return c;
err:
	SSL_CTX_free(c);
	return NULL;
}

void _httpd_ssl_destroy(ctx)
	SSL_CTX	*ctx;
{
	SSL_CTX_free(ctx);
}

static int _httpd_socket_wait(fd, sec, write)
	int	fd;
	int	sec;
	int	write;
{
	int rv;
	struct timeval timeout;

	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	timeout.tv_sec = sec;
	timeout.tv_usec = 0;

	while (((rv = select(fd + 1, write ? NULL : &fds, write ? &fds : NULL,
			     NULL, &timeout)) < 0) && (errno == EINTR))
	{
		continue;
	}

	if (rv <= 0)
		return 0;

	return 1;
}


SSL *_httpd_ssl_accept(ctx, fd)
	SSL_CTX	*ctx;
	int	fd;
{
	int rv, err;
	SSL *ssl;

	if (!ctx || fd < 0)
		return NULL;

	if ((ssl = SSL_new(ctx)))
	{
		if ((rv = SSL_set_fd(ssl, fd)) < 1)
		{
			SSL_free(ssl);
			ssl = NULL;
		}
		else
		{
			for (;;)
			{
				rv = SSL_accept(ssl);
				err = SSL_get_error(ssl, rv);

				if ((rv != 1) && (err == SSL_ERROR_WANT_READ ||
				    err == SSL_ERROR_WANT_WRITE))
				{
					if (_httpd_socket_wait(fd, 10, (err == SSL_ERROR_WANT_WRITE)))
						continue;
				}
				else if (rv == 1)
				{
					return ssl;
				}

				fprintf(stderr,
					"TLS: accept(%d) = failed: %s\n",
					fd, ERR_error_string(ERR_get_error(), NULL));

				SSL_free(ssl);
				ssl = NULL;
				break;
			}
		}
	}

	return ssl;
}

int _httpd_ssl_recv(ssl, buf, len)
	SSL	*ssl;
	char	*buf;
	int	len;
{
	int rv = SSL_read(ssl, buf, len);
	int err = SSL_get_error(ssl, 0);

	if ((rv == -1) && (err == SSL_ERROR_WANT_READ))
	{
		errno = EAGAIN;
		return -1;
	}

	return rv;
}

int _httpd_ssl_send(ssl, buf, len)
	SSL		*ssl;
	const char	*buf;
	int		len;
{
	int rv = SSL_write(ssl, buf, len);
	int err = SSL_get_error(ssl, 0);

	if ((rv == -1) && (err == SSL_ERROR_WANT_WRITE))
	{
		errno = EAGAIN;
		return -1;
	}

	return rv;
}

void _httpd_ssl_close(ssl)
	SSL	*ssl;
{
	if (ssl)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = NULL;
	}
}
#endif

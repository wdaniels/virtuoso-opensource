/*
 *  Dksestcpint.h
 *
 *  $Id$
 *
 *  Internal of Dksestcp.h
 *
 *  This file is part of the OpenLink Software Virtuoso Open-Source (VOS)
 *  project.
 *
 *  Copyright (C) 1998-2012 OpenLink Software
 *
 *  This project is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; only version 2 of the License, dated June 1991.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


#ifdef _SSL
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef WIN32
#define closesocket	close
#define ioctlsocket	ioctl
#endif

#ifdef _IPV6
typedef struct sockaddr_storage saddrin_t;

/* NB: We can no longer use sizeof(saddrin_t) in socket functions on all
 *     platforms (e.g. Solaris). Some implementations have a ss_len member
 *     in struct sockaddr_storage for convenience.
 *
 *     Linux doesn't currently have ss_len (but is less fussy about addrlen).
 */
#ifdef HAVE_SS_LEN
#define VOS_SALEN(p_addr) (((struct sockaddr_storage *) p_addr)->ss_len)
#else
#define VOS_SALEN(p_addr) ( \
  ((struct sockaddr_storage *) p_addr)->ss_family == AF_INET6 ? \
    sizeof(struct sockaddr_in6) : \
    ((struct sockaddr_storage *) p_addr)->ss_family == AF_INET ? \
      sizeof(struct sockaddr_in) : \
      sizeof(struct sockaddr_storage))
#endif

#define VOS_SAFAMILY(p_addr) (((struct sockaddr_storage *) p_addr)->ss_family)

#else
typedef struct sockaddr_in saddrin_t;

#define VOS_SALEN(p_addr) (sizeof(struct sockaddr_in))
#define VOS_SAFAMILY(p_addr) (AF_INET)
#endif

typedef struct sockaddr saddr_t;
#ifdef COM_UNIXSOCK
typedef struct sockaddr_un saddrun_t;
#endif

typedef union
{
  saddrin_t 	t;
#ifdef COM_UNIXSOCK
  saddrun_t 	u;
#endif
  saddr_t 	a;
} usaddr_t;
#define TCP_HOSTNAMELEN     100				   /* Something */



struct addresstruct
{
  usaddr_t 	a_serveraddr;
  char 		a_hostname[TCP_HOSTNAMELEN];
  int 		a_port;
};


struct connectionstruct
{
  int 		con_s;			/* socket descriptor, must be first field */
  usaddr_t 	con_clientaddr;
  int 		con_is_file;
#ifdef _SSL
  void *	ssl;
  void *	ssl_ctx;		/* SSL context, setted only for https listeners */
#endif
  void *	con_gzfile;
};

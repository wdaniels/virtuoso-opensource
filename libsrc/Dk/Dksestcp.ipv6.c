/*
 * IPv6 additional/alternative/patched implementations for Dksestcp.c
 *
 * This file is included at the end of Dksestcp.c when ipv6 support is enabled.
 *
 * Many of these changes are intended to replace the original functions
 * once fully tested and ported (i.e. this file is temporary).
 *
 * Contributing author Will Daniels <http://willdaniels.co.uk/#me>
 * License and copyright of Dksestcp.c apply respectively.

 */

#ifdef _IPV6

#ifdef WIN32
#include <WS2tcpip.h>
#endif

int
ip6_socket_name(struct sockaddr_storage *pss, char* buf, size_t max_buf)
{
	char ip[INET6_ADDRSTRLEN];
	unsigned short port = 0;
	
	if (pss->ss_family == AF_INET6)
	{
		struct in6_addr *p_addr;
		p_addr = &((struct sockaddr_in6 *) pss)->sin6_addr;
		port = ntohs(((struct sockaddr_in6 *) pss)->sin6_port);
		
		if ((inet_ntop(AF_INET6, p_addr, &ip[0], INET6_ADDRSTRLEN)))
		{
			if (strcmp(ip, "::") == 0)
			{
				ip[0] = 0; // match legacy behaviour for "any"
				snprintf(buf, max_buf, ":%d", port);
			}
			else
			{
				snprintf(buf, max_buf, "[%s]:%d", &ip[0], port);
			}
		}
	}
	else if (pss->ss_family == AF_INET)
	{
		struct in_addr *p_addr;
		p_addr = &((struct sockaddr_in *) pss)->sin_addr;
		port = ntohs(((struct sockaddr_in *) pss)->sin_port);
		
		if ((inet_ntop(AF_INET, p_addr, &ip[0], INET6_ADDRSTRLEN)))
			snprintf(buf, max_buf, "%s:%d", &ip[0], port);
	}
	else
	{
		log_error(
			"ip6_socket_name: unexpected socket family %d",
			pss->ss_family
		);
	}

	return (int) port;
}


void
ip6_build_hostname(char *p_host, char *p_port, char *buf, size_t max_buf)
{
	if (p_host && !strlen(p_host))
		p_host = 0;

	if (p_port && !strlen(p_port))
		p_port = 0;

	if (p_host && strchr(p_host, ':'))
		snprintf(buf, max_buf, "[%s]:%s", p_host, p_port);
	else if (p_host && p_port)
		snprintf(buf, max_buf, "%s:%s", p_host, p_port);
	else if (p_port)
		snprintf(buf, max_buf, ":%s", p_port);
	else if (p_host)
		snprintf(buf, max_buf, "%s", p_host);
	else
		*buf = 0;
}


void
ip6_split_hostname(char *p_fhost, char *buf_name, size_t max_name, char *buf_port, size_t max_port, int def_port)
{
	char *p_port, *p_name, *p_host;

	p_host = strdup(p_fhost);
	p_name = p_host;

	// change any final space delimiter (for port) to a colon
	if ((p_port = strrchr(p_name, ' ')))
		*p_port = ':';
		
	if ((p_port = strrchr(p_name, ':')))
	{
		// if the first colon is not the last assume ipv6
		if (p_port != strchr(p_name, ':'))
		{
			if (p_name[0] == '[' && strchr(p_name, ']'))
			{
				// ipv6 [host]:port syntax, so drop the brackets
				p_name++;
				if (p_port > p_name) // for sanity only
					*(p_port - 1) = 0;
			}
			else
			{
				p_port = NULL; // cannot assume this is a port delimiter
			}
		}
	}

	if (p_port == NULL)
	{
		// a purely numeric string is a port number for any domain
		if (alldigits(p_name))
		{
			p_port = p_fhost;
			*p_name = 0;
		}
	}
	else
	{
		*p_port++ = 0; // terminate host string at the delimiter
	}
	
	snprintf(buf_name, max_name, "%s", p_name);
	if (p_port)
		snprintf(buf_port, max_port, "%s", p_port);
	else
		snprintf(buf_port, max_port, "%d", def_port);

	if (p_host)
		free(p_host);
}


void
ip6_address_name(const char *ip, char *out_name, size_t max_name)
{
	int res;
	struct sockaddr_storage ss;
	struct in6_addr *paddr6;

	memset(&ss, 0, sizeof(struct sockaddr_storage));
	strncpy(out_name, ip, max_name);

	// first parse the ip string into the correct data structure...
	paddr6 = &((struct sockaddr_in6 *) &ss)->sin6_addr;

	res = inet_pton(AF_INET6, ip, paddr6);
	if (res == 1)
	{
		ss.ss_family = AF_INET6; // success ipv6
#ifdef HAVE_SS_LEN
		ss.ss_len = sizeof(struct sockaddr_in6);
#endif
	}
	else
	{
		struct in_addr *paddr4;
		paddr4 = &((struct sockaddr_in *) &ss)->sin_addr;
		
		res = inet_pton(AF_INET, ip, paddr4);
		if (res < 1)
		{
			log_error(
				"ip6_address_name: inet_pton failed (%d) for \"%s\"",
				res, ip
			);
			return;
		}
		ss.ss_family = AF_INET; // success ipv4
#ifdef HAVE_SS_LEN
		ss.ss_len = sizeof(struct sockaddr_in);
#endif
	}

	// now try the address-to-name translation...
	res = getnameinfo(
		(struct sockaddr *) &ss, VOS_SALEN(&ss),
		out_name, max_name, NULL, 0, 0
	);

	if (res)
	{
		log_debug(
			"ip6_address_name: getnameinfo failed #%x (%s) for \"%s\"",
			res, gai_strerror(res), ip
		);
	}
}

static int
tcpses_set_address (session_t * ses, char *addrinfo1)
{
	saddrin_t *p_addr;
	char *p_name, port[NI_MAXSERV];
	size_t max_name;
	int iport;

	init_tcpip ();
	// TODO: check whether addrinfo is used elsewhere and ditch it :S
	strncpy (addrinfo, addrinfo1, sizeof (addrinfo));
	addrinfo[sizeof(addrinfo) - 1] = 0;

	TCP_CHK (ses);

	p_addr = &(ses->ses_device->dev_address->a_serveraddr.t);
	p_name = ses->ses_device->dev_address->a_hostname;
	memset(p_addr, 0, sizeof(saddrin_t));

	SESSTAT_CLR (ses, SST_OK);

	max_name = sizeof(ses->ses_device->dev_address->a_hostname);
	ip6_split_hostname(addrinfo1, p_name, max_name, port, sizeof(port), 0);

	// TODO: consider supporting service names here?
	if (!alldigits((char *) &port))
	{
		return (SER_FAIL); // absent or mangled port number
	}

	iport = atoi((char *) &port);
	ses->ses_device->dev_address->a_port = iport;

	/*
	 * A null hostname signifies "any" interface. Typically we would want
	 * to use the ipv6 unspecified address :: in dual-stack mode so that
	 * this covers both ipv4 and ipv6 connections on any interface.
	 *
	 * Single-stack nodes (and platforms not supporting dual-mode sockets)
	 * currently should specify 0.0.0.0 or :: explicity (and as applicable)
	 * in the VHOST or INI configs to avoid using dual-mode sockets.
	 *
	 * Compilation of ipv6 support implies use with a ipv6-capable kernel
	 * (regardless of which stacks are currently enabled). Separate binaries
	 * must be built with --disable-ipv6 for use on older platforms that
	 * don't understand the new data structures.
	 */

	if (!strcmp(p_name, "0.0.0.0"))
	{
		// NB: use htonl on s_addr if changing from ANY (redundant for zero)
		struct sockaddr_in *p_addr4 = (struct sockaddr_in *) p_addr;
		p_addr4->sin_family = AF_INET;
		p_addr4->sin_addr.s_addr = INADDR_ANY;
		p_addr4->sin_port = htons(iport);
#ifdef HAVE_SS_LEN
		p_addr->ss_len = sizeof(struct sockaddr_in);
#endif
	}
	else if ((p_name[0] == 0) || !strcmp(p_name, "::"))
	{
		struct sockaddr_in6 *p_addr6 = (struct sockaddr_in6 *) p_addr;
		p_addr6->sin6_family = AF_INET6;
		p_addr6->sin6_addr = in6addr_any;
		p_addr6->sin6_port = htons(iport);
#ifdef HAVE_SS_LEN
		p_addr->ss_len = sizeof(struct sockaddr_in6);
#endif
	}
	else
	{
		in_addr_t addr;
		int res = inet_pton(AF_INET, p_name, &addr);
		if (res > 0)
		{
			// ipv4 address
			struct sockaddr_in *p_addr4 = (struct sockaddr_in *) p_addr;
			memcpy(&p_addr4->sin_addr, &addr, sizeof(addr));
			p_addr4->sin_family = AF_INET;
			p_addr4->sin_port = htons(iport);
		}
		else
		{
			// should be either a hostname or ipv6 address
			int res;
			struct addrinfo hints;
			struct addrinfo *result, *rp;

			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = AI_ADDRCONFIG;
			hints.ai_family = (addrinfo1[0] == '[') ? AF_INET6 : AF_UNSPEC;
			hints.ai_protocol = IPPROTO_TCP;

			res = getaddrinfo(p_name, (char *) &port, &hints, &result);
			if(res != 0)
			{
				log_error(
					"getaddrinfo: failed, #%x (%s) for host \"%s\"",
					res, gai_strerror(res), p_name
				);
				SESSTAT_CLR (ses, SST_OK);
				return (SER_FAIL);
			}
			else if ((rp = result))
			{
				memcpy(p_addr, rp->ai_addr, rp->ai_addrlen);
				freeaddrinfo(result);
			}
		}
	}
	
	SESSTAT_SET (ses, SST_OK);

	return (SER_SUCC);
}


int
tcpses_getsockname (session_t * ses, char *buf_out, int buf_out_len)
{
	int s = tcpses_get_fd(ses);
	char buf[150];

	buf[0] = 0;

	if (ses->ses_class == SESCLASS_TCPIP || ses->ses_class == SESCLASS_UDPIP)
	{
		saddrin_t ss;
		socklen_t len = sizeof(ss);

		if (!getsockname(s, (struct sockaddr *) &ss, &len))
			ip6_socket_name(&ss, buf, sizeof(buf));
		else
			return -1;
	}
#ifdef COM_UNIXSOCK
	else if (ses->ses_class == SESCLASS_UNIX)
	{
		struct sockaddr_un sa;
		socklen_t len = sizeof (sa);

		if (!getsockname(s, (struct sockaddr *) &sa, &len))
		{
			strncpy(buf, sa.sun_path, sizeof(buf));
			buf[sizeof(buf) - 1] = 0;
		}
		else
			return -1;
	}
#endif
	else
		return -1;

	if (buf_out_len && buf_out)
	{
		strncpy (buf_out, buf, buf_out_len);
		buf[buf_out_len - 1] = 0;
	}

	return 0;
}


int
tcpses_client_port (session_t * ses)
{
	saddrin_t *pss;
	unsigned short port = 0;
	
	if (ses->ses_class == SESCLASS_UNIX)
	{
		return (unsigned short) -1;
	}
	else if (ses->ses_class == SESCLASS_TCPIP || ses->ses_class == SESCLASS_UDPIP)
	{
		pss = (saddrin_t *) &(ses->ses_device->dev_connection->con_clientaddr.t);

		// NB: sin_port and sin6_port probably at the same offset,
		//     but not sure if that is a safe/portable assumption.
		if (pss->ss_family == AF_INET)
			port = ((struct sockaddr_in *) pss)->sin_port;
		else if (pss->ss_family == AF_INET6)
			port = ((struct sockaddr_in6 *) pss)->sin6_port;
	}

	return ntohs(port);
}


void
tcpses_print_client_ip (session_t * ses, char *buf, int buf_len)
{
	saddrin_t *pss;

	if (ses->ses_class == SESCLASS_UNIX)
	{
		// TODO: consider implications for ipv6-only stack...
		//       what is it used for with sockets? http map?
		snprintf (buf, buf_len, "127.0.0.1");
	}
	else if (ses->ses_class == SESCLASS_TCPIP || ses->ses_class == SESCLASS_UDPIP)
	{
		char ip[INET6_ADDRSTRLEN];
		pss = (saddrin_t *) &(ses->ses_device->dev_connection->con_clientaddr.t);

		if (pss->ss_family == AF_INET6)
		{
			struct in6_addr addr = ((struct sockaddr_in6 *) pss)->sin6_addr;
			inet_ntop(AF_INET6, &addr, &ip[0], INET6_ADDRSTRLEN);
		}
		else
		{
			struct in_addr addr = ((struct sockaddr_in *) pss)->sin_addr;
			inet_ntop(AF_INET, &addr, &ip[0], INET6_ADDRSTRLEN);
		}

		snprintf(buf, buf_len, "%s", &ip[0]);
	}
}


int
tcpses_addr_info (session_t * ses, char *buf, size_t max_buf, int deflt, int from)
{
	// TODO: check inputs? what is deflt?
	// NB: must use the stored a_hostname not the socket ip

	char *hn;
	int port = 0;
	saddrin_t *pss;

	if (!ses || !ses->ses_device || !ses->ses_device->dev_accepted_address)
		return 0;
	if (ses->ses_class == SESCLASS_UNIX)
		return 0;

	if (from)
	{
		pss = (saddrin_t *) &ses->ses_device->dev_accepted_address->a_serveraddr.t;
		hn = ses->ses_device->dev_accepted_address->a_hostname;
	}
	else
	{
		pss = (saddrin_t *) &ses->ses_device->dev_address->a_serveraddr.t;
		hn = ses->ses_device->dev_address->a_hostname;
	}

	if (pss->ss_family == AF_INET)
		port = ntohs(((struct sockaddr_in *) pss)->sin_port);
	if (pss->ss_family == AF_INET6)
		port = ntohs(((struct sockaddr_in6 *) pss)->sin6_port);

	if (strchr(hn, ':'))
		snprintf(buf, max_buf, "[%s]:%d", hn, port);
	else
		snprintf(buf, max_buf, "%s:%d", hn, port);

	return port;
}


#ifdef PCTCP
// TODO: re-implement init_pctcp once Windows details are sorted out
#endif

#endif // _IPV6


/*
 * IPv6 additional/alternative/patched implementations for http.c
 *
 * This file is included at the end of http.c when ipv6 support is enabled.
 *
 * Many of these changes are intended to replace the original functions
 * once fully tested and ported (i.e. this file is temporary).
 *
 * Contributing author Will Daniels <http://willdaniels.co.uk/#me>
 * License and copyright of http.c apply respectively.
 */

#ifdef _IPV6

void
ws_set_phy_path (ws_connection_t * ws, int dir, char * vsp_path)
{
	http_trace(("ws_set_phy_path: called for vsp path \"%s\"", vsp_path));

	caddr_t lpath = NULL, ppath = NULL, host_hf = NULL, host = NULL;
	char listen_host [128];
	struct sockaddr_storage ss;
	char nif[100]; /* network interface address */
	int s, port = 0, is_https = 0;
#ifdef _SSL
	SSL *ssl = NULL;
#endif
	socklen_t len = sizeof (ss);

	if (!ws)
		return;

	s = tcpses_get_fd (ws->ws_session->dks_session);
	if (!getsockname (s, (struct sockaddr *) &ss, &len))
		ip6_socket_name(&ss, nif, sizeof(nif));
	else
		nif[0] = 0;

#ifdef _SSL
	ssl = (SSL *) tcpses_get_ssl (ws->ws_session->dks_session);
	is_https = (NULL != ssl);
#endif

	tcpses_addr_info (ws->ws_session->dks_session, listen_host, sizeof (listen_host), 80, 1);

	if (NULL == (host_hf = ws_mime_header_field (ws->ws_lines, "X-Forwarded-Host", NULL, 1)))
		host_hf = ws_mime_header_field (ws->ws_lines, "Host", NULL, 1);
	if (NULL == host_hf)
		host_hf = box_dv_short_string (listen_host);

	host = http_host_normalize_1 (host_hf, 0, (is_https ? 443 : 80), IS_GATEWAY_PROXY (ws) ? port : 0);
	http_trace (("ws_set_phy_path: host hf: %s, host nfo:, %s nif: %s\n", host, listen_host, nif));

	if (!vsp_path)
	{
		lpath = strchr (ws->ws_req_line, '\x20');
		while (lpath && *lpath && isspace (*lpath))
			lpath++;
	}
	else
		lpath = vsp_path;

	if (0 != nif[0])
		ppath = get_http_map (&(ws->ws_map), lpath, dir, host, nif); /* trying vhost & ip */
	if (NULL == ws->ws_map)
	{
		dk_free_box (ppath); ppath = NULL;
		ppath = get_http_map (&(ws->ws_map), lpath, dir, host, listen_host); /* try virtual host */
	}
	if ((listen_host[0] == ':' || !strncmp(listen_host, "[::]", 4)) && NULL == ws->ws_map)
	{
		dk_free_box (ppath); ppath = NULL;
		ppath = get_http_map (&(ws->ws_map), lpath, dir, "*all*", listen_host);
	}
	/* try the default directory for listen NIF */
	else if (listen_host[0] != ':' && strncmp(listen_host, "[::]", 4) && NULL == ws->ws_map)
	{
		dk_free_box (ppath); ppath = NULL;
		ppath = get_http_map (&(ws->ws_map), lpath, dir, listen_host, listen_host);
	}

	http_trace(("ws_set_phy_path: resolved to physical path \"%s\"", ppath));

	ws->ws_p_path_string = ppath;
	ws->ws_p_path = (caddr_t *) http_path_to_array (ppath, 1);
	dk_free_box (host);
	dk_free_box (host_hf);
}


static caddr_t
ws_get_http_map (ws_connection_t * ws, int dir, caddr_t lpath, int set_map)
{
	caddr_t ppath = NULL, host_hf = NULL, host = NULL;
	char listen_host [128];
	struct sockaddr_storage ss;
	char nif[100] = {0}; /* network interface address */
	int s;
	int is_https = 0;
#ifdef _SSL
  SSL *ssl = NULL;
#endif
	socklen_t len = sizeof (ss);
	ws_http_map_t * pmap = NULL;
	ws_http_map_t ** map = set_map ? &(ws->ws_map) : &pmap;
	int port = 0;

	if (!ws)
		return NULL;

	s = tcpses_get_fd (ws->ws_session->dks_session);
	if (!getsockname (s, (struct sockaddr *) &ss, &len))
		ip6_socket_name(&ss, nif, sizeof(nif));
	else
		nif[0] = 0;

	http_trace(("ws_get_http_map: socket name of null interface is \"%s\"", nif));

	tcpses_addr_info (ws->ws_session->dks_session, listen_host, sizeof (listen_host), 80, 1);
	if (NULL == (host_hf = ws_mime_header_field (ws->ws_lines, "X-Forwarded-Host", NULL, 1)))
		host_hf = ws_mime_header_field (ws->ws_lines, "Host", NULL, 1);
	if (NULL == host_hf)
		host_hf = box_dv_short_string (listen_host);
#ifdef _SSL
	ssl = (SSL *) tcpses_get_ssl (ws->ws_session->dks_session);
	is_https = (NULL != ssl);
#endif
	host = http_host_normalize_1 (host_hf, 0, (is_https ? 443 : 80), IS_GATEWAY_PROXY (ws) ? port : 0);

	if (0 != nif[0])
	{
		ppath = get_http_map (map, lpath, dir, host, nif); /* trying vhost & ip */
	}
	if (NULL == *map)
	{
		dk_free_box (ppath); ppath = NULL;
		ppath = get_http_map (map, lpath, dir, host, listen_host); /* try virtual host */
	}
	if ((listen_host[0] == ':' || !strncmp(listen_host, "[::]", 4)) && NULL == *map)
	{
		dk_free_box (ppath); ppath = NULL;
		ppath = get_http_map (map, lpath, dir, "*all*", listen_host);
	}
	/* try the default directory for listen NIF */
	else if (listen_host[0] != ':' && strncmp(listen_host, "[::]", 4) && NULL == *map)
	{
		dk_free_box (ppath); ppath = NULL;
		ppath = get_http_map (map, lpath, dir, listen_host, listen_host);
	}
	dk_free_box (host);
	dk_free_box (host_hf);

	http_trace(("ws_get_http_map: resolved and returning physical path \"%s\"", ppath));
	return ppath;
}


caddr_t
ws_gethostbyaddr (const char *ip)
{
	char name[NI_MAXHOST];
	ip6_address_name(ip, name, sizeof(name));
	return box_dv_short_string(name);
}


caddr_t
http_host_normalize_1 (caddr_t host, int to_ip, int def_port, int physical_port)
{
	// TODO: what's physical_port all about? check to_ip really deprecated!

	caddr_t _host;
	char name[NI_MAXHOST], port[NI_MAXSERV], buf[NI_MAXHOST + NI_MAXSERV + 2];

	if (!host)
		return NULL;

	if (!strcmp(host, "*ini*") && http_port)
		_host = http_port;
	else if (!strcmp(host, "*sslini*") && https_port)
		_host = https_port;
	else
		_host = host;

	ip6_split_hostname(_host, name, sizeof(name), port, sizeof(port), def_port);
	ip6_build_hostname(name, port, buf, sizeof(buf));

	return box_dv_short_string(buf);
}


caddr_t
http_virtual_host_normalize (caddr_t _host, caddr_t lhost)
{
	caddr_t endpoint;

	char vname[NI_MAXHOST], vport[NI_MAXSERV];
	char lname[NI_MAXHOST], lport[NI_MAXSERV];

	char *p_name, *p_port;
	char buf[NI_MAXHOST + NI_MAXSERV + 2];

	if (!_host || !lhost)
		return NULL;

	/* they are same, both are the default */
	if (!strcmp (_host, lhost))
		return http_host_normalize(_host, 0);

	ip6_split_hostname(_host, vname, sizeof(vname), vport, sizeof(vport), 0);

	if (!strcmp(lhost, "*ini*") && http_port)
		endpoint = http_port;
	else if (!strcmp(lhost, "*sslini*") && https_port)
		endpoint = https_port;
	else
		endpoint = lhost;

	if (!endpoint)
		return NULL;

	ip6_split_hostname(endpoint, lname, sizeof(lname), lport, sizeof(lport), 80);

	p_name = (char *) (strlen(lname) ? &lname : &vname);
	p_port = (char *) (atoi(lport) ? &lport : &vport);

	ip6_build_hostname(p_name, p_port, buf, sizeof(buf));

	return box_dv_short_string(buf);
}


caddr_t *
box_tpcip_get_interfaces ()
{
	dk_set_t set = NULL;

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>

	struct ifaddrs *ifaddr, *ifa;
	int family, res;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1)
		dbg_perror("getifaddrs");

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		/*
		 * Here we exclude some special ipv6 address classes;
		 *
		 *  1. non-routable link-local addresses
		 *  2. the :: (unspecified/any) address if it turns up
		 *
		 * Not all platforms enumerate the :: address in getifaddrs so we
		 * add it manually to lists in the conductor interface.
		 */
		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET6)
		{
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) (ifa->ifa_addr);
			if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)
				|| IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr)
			)
				continue;
		}

		if (family == AF_INET || family == AF_INET6)
		{
			res = getnameinfo(
				ifa->ifa_addr,
				(family == AF_INET) ? sizeof(struct sockaddr_in) :
				                      sizeof(struct sockaddr_in6),
				host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST
			);
			if (res != 0)
			{
				log_error(
					"box_tpcip_get_interfaces: getnameinfo() failed: %s",
					gai_strerror(res)
				);
			}
			dk_set_push(&set, box_string(host));
		}
	}

	freeifaddrs(ifaddr);
#else
#error "Unsupported interface enumeration on this platform."
#endif

	return (caddr_t *) list_to_array(dk_set_nreverse(set));
}


caddr_t
get_http_map (ws_http_map_t ** ws_map, char * lpath, int dir, char * host, char * lhost)
{
	http_trace(("get_http_map: called for lpath \"%s\", host \"%s\", lhost \"%s\"", lpath, host, lhost));

	caddr_t * ret = NULL;
	ws_http_map_t ** last_match = NULL;
	int inx, len, elm, rlen, n;
	caddr_t res = NULL;
	caddr_t * paths = (caddr_t *) http_path_to_array (lpath, 0);
	caddr_t path_str;
	if (!ws_map)
		return NULL;
	*ws_map = NULL; /* first clear old map entry */
	if (paths)
		len = BOX_ELEMENTS (paths);
	else
		len = 0;
	inx = 0;
	elm = 0;
	do
	{
		path_str = get_path_elms (paths, inx++, host, lhost);
		last_match = (ws_http_map_t **) id_hash_get (http_map, (caddr_t) & path_str);
		http_trace(("get_http_map: [%d] trying w/h host hf: %s %p", (inx - 1), path_str, last_match));
		if (last_match && *last_match)
		{
			ret = &((*last_match)->hm_p_path);
			*ws_map = *last_match;
			elm = inx;
		}
		dk_free_box (path_str);
	}
	while (inx <= len);

	rlen = 0;

	if (ret)
		rlen += box_length (*ret);
	else
	{
		path_str =  get_path_elms (paths, len, NULL, NULL);
		rlen += box_length (path_str);
		if (dir && 0 != strcmp (path_str, "/"))
			rlen++;
		res = dk_alloc_box (rlen , DV_SHORT_STRING);
		strcpy_box_ck (res, path_str);
		if (dir && 0 != strcmp (res, "/"))
			strcat_box_ck (res, "/");
		dk_free_box (path_str);
	}
	if (ret != NULL && last_match == NULL && elm > 0 && !(*ws_map)->hm_no_inherit)
    {
		if (rlen > 1 && '/' == (*ret)[rlen - 2])
			rlen--;
		elm --;
		for (n = elm; n < len; n++)
			rlen += box_length (paths [n]);
		if (dir)
			rlen ++;
		res = dk_alloc_box (rlen , DV_SHORT_STRING);
		strcpy_box_ck (res, *ret);
		if (res [strlen (res) - 1] != '/')
			strcat_box_ck (res , "/");
		while (elm < len)
		{
			strcat_box_ck (res, paths [elm]);
			if ((elm < len - 1) /*|| ((elm == len - 1) && (lpath [strlen (lpath) - 1] == '/'))*/)
				strcat_box_ck (res, "/");
			elm++;
		}
		if (dir)
			strcat_box_ck (res, "/");
	}
	if (ret != NULL && (last_match != NULL || (*ws_map)->hm_no_inherit) && elm > 0)
	{
		res = dk_alloc_box (rlen , DV_SHORT_STRING);
		strcpy_box_ck (res, *ret);
	}
	dk_free_tree ((box_t) paths);

	http_trace(("get_http_map: returning \"%s\"", (char *) res);)
  return res;
}
#endif

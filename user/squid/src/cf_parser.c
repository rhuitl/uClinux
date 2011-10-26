/*
 * Generated automatically from cf.data by ./cf_gen
 *
 * Abstract: This file contains routines used to configure the
 *           variables in the squid server.
 */

static void
default_line(const char *s)
{
	LOCAL_ARRAY(char, tmp_line, BUFSIZ);
	xstrncpy(tmp_line, s, BUFSIZ);
	xstrncpy(config_input_line, s, BUFSIZ);
	config_lineno++;
	parse_line(tmp_line);
}
static void
default_all(void)
{
	cfg_filename = "Default Configuration";
	config_lineno = 0;
	/* No default for http_port */
#if USE_SSL
	/* No default for https_port */
#endif
#if USE_SSL
	default_line("ssl_unclean_shutdown off");
#endif
	default_line("icp_port 3130");
#if USE_HTCP
	default_line("htcp_port 4827");
#endif
	/* No default for mcast_groups */
	default_line("udp_incoming_address 0.0.0.0");
	default_line("udp_outgoing_address 255.255.255.255");
	/* No default for cache_peer */
	/* No default for cache_peer_domain */
	/* No default for neighbor_type_domain */
	default_line("icp_query_timeout 0");
	default_line("maximum_icp_query_timeout 2000");
	default_line("mcast_icp_query_timeout 2000");
	default_line("dead_peer_timeout 10 seconds");
	/* No default for hierarchy_stoplist */
	/* No default for no_cache */
	default_line("cache_mem 2 MB");
	default_line("cache_swap_low 90");
	default_line("cache_swap_high 95");
	default_line("maximum_object_size 4096 KB");
	default_line("minimum_object_size 0 KB");
	default_line("maximum_object_size_in_memory 8 KB");
	default_line("ipcache_size 1024");
	default_line("ipcache_low 90");
	default_line("ipcache_high 95");
	default_line("fqdncache_size 1024");
	default_line("cache_replacement_policy lru");
	default_line("memory_replacement_policy lru");
	/* No default for cache_dir */
	default_line("cache_access_log /usr/squid/logs/access.log");
	default_line("cache_log /usr/squid/logs/cache.log");
	default_line("cache_store_log /usr/squid/logs/store.log");
	/* No default for cache_swap_log */
	default_line("emulate_httpd_log off");
	default_line("log_ip_on_direct on");
	default_line("mime_table /usr/squid/etc/mime.conf");
	default_line("log_mime_hdrs off");
#if USE_USERAGENT_LOG
	/* No default for useragent_log */
#endif
#if USE_REFERER_LOG
	/* No default for referer_log */
#endif
	default_line("pid_filename /var/run/squid.pid");
	default_line("debug_options ALL,1");
	default_line("log_fqdn off");
	default_line("client_netmask 255.255.255.255");
	default_line("ftp_user Squid@");
	default_line("ftp_list_width 32");
	default_line("ftp_passive on");
	default_line("ftp_sanitycheck on");
#if USE_DNSSERVERS
	default_line("cache_dns_program /usr/squid/bin/dnsserver");
#endif
#if USE_DNSSERVERS
	default_line("dns_children 5");
#endif
#if !USE_DNSSERVERS
	default_line("dns_retransmit_interval 5 seconds");
#endif
#if !USE_DNSSERVERS
	default_line("dns_timeout 5 minutes");
#endif
#if USE_DNSSERVERS
	default_line("dns_defnames off");
#endif
	/* No default for dns_nameservers */
	default_line("hosts_file /etc/hosts");
	default_line("diskd_program @DEFAULT_DISKD@");
#if USE_UNLINKD
	default_line("unlinkd_program /usr/squid/bin/unlinkd");
#endif
#if USE_ICMP
	default_line("pinger_program /usr/squid/bin/pinger");
#endif
	/* No default for redirect_program */
	default_line("redirect_children 5");
	default_line("redirect_rewrites_host_header on");
	/* No default for redirector_access */
	/* No default for auth_param */
	default_line("authenticate_cache_garbage_interval 1 hour");
	default_line("authenticate_ttl 1 hour");
	default_line("authenticate_ip_ttl 0 seconds");
	/* No default for external_acl_type */
	/* No default for wais_relay_host */
	default_line("wais_relay_port 0");
	default_line("request_header_max_size 10 KB");
	default_line("request_body_max_size 0 KB");
	/* No default for refresh_pattern */
	default_line("quick_abort_min 16 KB");
	default_line("quick_abort_max 16 KB");
	default_line("quick_abort_pct 95");
	default_line("negative_ttl 5 minutes");
	default_line("positive_dns_ttl 6 hours");
	default_line("negative_dns_ttl 5 minutes");
	default_line("range_offset_limit 0 KB");
	default_line("connect_timeout 2 minutes");
	default_line("peer_connect_timeout 30 seconds");
	default_line("read_timeout 15 minutes");
	default_line("request_timeout 5 minutes");
	default_line("persistent_request_timeout 1 minute");
	default_line("client_lifetime 1 day");
	default_line("half_closed_clients on");
	default_line("pconn_timeout 120 seconds");
#if USE_IDENT
	default_line("ident_timeout 10 seconds");
#endif
	default_line("shutdown_lifetime 30 seconds");
	/* No default for acl */
	/* No default for http_access */
	/* No default for http_reply_access */
	/* No default for icp_access */
	/* No default for miss_access */
	/* No default for cache_peer_access */
#if USE_IDENT
	/* No default for ident_lookup_access */
#endif
	/* No default for tcp_outgoing_tos */
	/* No default for tcp_outgoing_address */
	/* No default for reply_body_max_size */
	default_line("cache_mgr webmaster");
	default_line("cache_effective_user nobody");
	/* No default for cache_effective_group */
	/* No default for visible_hostname */
	/* No default for unique_hostname */
	/* No default for hostname_aliases */
	default_line("announce_period 0");
	default_line("announce_host tracker.ircache.net");
	/* No default for announce_file */
	default_line("announce_port 3131");
	/* No default for httpd_accel_host */
	default_line("httpd_accel_port 80");
	default_line("httpd_accel_single_host off");
	default_line("httpd_accel_with_proxy off");
	default_line("httpd_accel_uses_host_header off");
	/* No default for dns_testnames */
	default_line("logfile_rotate 10");
	/* No default for append_domain */
	default_line("tcp_recv_bufsize 0 bytes");
	/* No default for err_html_text */
	/* No default for deny_info */
	default_line("memory_pools on");
	/* No default for memory_pools_limit */
	default_line("forwarded_for on");
	default_line("log_icp_queries on");
	default_line("icp_hit_stale off");
	default_line("minimum_direct_hops 4");
	default_line("minimum_direct_rtt 400");
	/* No default for cachemgr_passwd */
	default_line("store_avg_object_size 13 KB");
	default_line("store_objects_per_bucket 20");
	default_line("client_db on");
	default_line("netdb_low 900");
	default_line("netdb_high 1000");
	default_line("netdb_ping_period 5 minutes");
	default_line("query_icmp off");
	default_line("test_reachability off");
	default_line("buffered_logs off");
#if HTTP_VIOLATIONS
	default_line("reload_into_ims off");
#endif
	/* No default for always_direct */
	/* No default for never_direct */
#if HTTP_VIOLATIONS
	/* No default for header_access */
#endif
#if HTTP_VIOLATIONS
	/* No default for header_replace */
#endif
	default_line("icon_directory /usr/squid/icons");
	default_line("error_directory /usr/squid/errors");
	default_line("minimum_retry_timeout 5 seconds");
	default_line("maximum_single_addr_tries 3");
#if SQUID_SNMP
	default_line("snmp_port 3401");
#endif
#if SQUID_SNMP
	/* No default for snmp_access */
#endif
#if SQUID_SNMP
	default_line("snmp_incoming_address 0.0.0.0");
#endif
#if SQUID_SNMP
	default_line("snmp_outgoing_address 255.255.255.255");
#endif
	default_line("as_whois_server whois.ra.net");
#if USE_WCCP
	default_line("wccp_router 0.0.0.0");
#endif
#if USE_WCCP
	default_line("wccp_version 4");
#endif
#if USE_WCCP
	default_line("wccp_incoming_address 0.0.0.0");
#endif
#if USE_WCCP
	default_line("wccp_outgoing_address 255.255.255.255");
#endif
#if DELAY_POOLS
	default_line("delay_pools 0");
#endif
#if DELAY_POOLS
	/* No default for delay_class */
#endif
#if DELAY_POOLS
	/* No default for delay_access */
#endif
#if DELAY_POOLS
	/* No default for delay_parameters */
#endif
#if DELAY_POOLS
	default_line("delay_initial_bucket_level 50");
#endif
	default_line("incoming_icp_average 6");
	default_line("incoming_http_average 4");
	default_line("incoming_dns_average 4");
	default_line("min_icp_poll_cnt 8");
	default_line("min_dns_poll_cnt 8");
	default_line("min_http_poll_cnt 8");
	default_line("max_open_disk_fds 0");
	default_line("offline_mode off");
	default_line("uri_whitespace strip");
	/* No default for broken_posts */
#if MULTICAST_MISS_STREAM
	default_line("mcast_miss_addr 255.255.255.255");
#endif
#if MULTICAST_MISS_TTL
	default_line("mcast_miss_ttl 16");
#endif
#if MULTICAST_MISS_STREAM
	default_line("mcast_miss_port 3135");
#endif
#if MULTICAST_MISS_STREAM
	default_line("mcast_miss_encode_key XXXXXXXXXXXXXXXX");
#endif
	default_line("nonhierarchical_direct on");
	default_line("prefer_direct off");
	default_line("strip_query_terms on");
	/* No default for coredump_dir */
	default_line("redirector_bypass off");
	default_line("ignore_unknown_nameservers on");
#if USE_CACHE_DIGESTS
	default_line("digest_generation on");
#endif
#if USE_CACHE_DIGESTS
	default_line("digest_bits_per_entry 5");
#endif
#if USE_CACHE_DIGESTS
	default_line("digest_rebuild_period 1 hour");
#endif
#if USE_CACHE_DIGESTS
	default_line("digest_rewrite_period 1 hour");
#endif
#if USE_CACHE_DIGESTS
	default_line("digest_swapout_chunk_size 4096 bytes");
#endif
#if USE_CACHE_DIGESTS
	default_line("digest_rebuild_chunk_percentage 10");
#endif
	/* No default for chroot */
	default_line("client_persistent_connections on");
	default_line("server_persistent_connections on");
	default_line("pipeline_prefetch off");
	/* No default for extension_methods */
	default_line("request_entities off");
	default_line("high_response_time_warning 0");
	default_line("high_page_fault_warning 0");
	default_line("high_memory_warning 0");
	default_line("store_dir_select_algorithm least-load");
#if WIP_FWD_LOG
	/* No default for forward_log */
#endif
	default_line("ie_refresh off");
	default_line("vary_ignore_expire off");
	default_line("sleep_after_fork 0");
	cfg_filename = NULL;
}

static void
defaults_if_none(void)
{
	if (check_null_sockaddr_in_list(Config.Sockaddr.http))
		default_line("http_port 3128");
	if (check_null_cachedir(Config.cacheSwap))
		default_line("cache_dir ufs /usr/squid/cache 100 16 256");
	if (check_null_acl_access(Config.accessList.http))
		default_line("http_access deny all");
	if (check_null_acl_access(Config.accessList.reply))
		default_line("http_reply_access allow all");
	if (check_null_acl_access(Config.accessList.icp))
		default_line("icp_access deny all");
#if USE_IDENT
	if (check_null_acl_access(Config.accessList.identLookup))
		default_line("ident_lookup_access deny all");
#endif
	if (check_null_body_size_t(Config.ReplyBodySize))
		default_line("reply_body_max_size 0 allow all");
	if (check_null_wordlist(Config.dns_testname_list))
		default_line("dns_testnames netscape.com internic.net nlanr.net microsoft.com");
#if SQUID_SNMP
	if (check_null_acl_access(Config.accessList.snmp))
		default_line("snmp_access deny all");
#endif
	if (check_null_string(Config.as_whois_server))
		default_line("as_whois_server whois.ra.net");
	if (check_null_string(Config.coredump_dir))
		default_line("coredump_dir none");
}

static int
parse_line(char *buff)
{
	int	result = 1;
	char	*token;
	debug(0,10)("parse_line: %s\n", buff);
	if ((token = strtok(buff, w_space)) == NULL)
		(void) 0;	/* ignore empty lines */
	else if (!strcmp(token, "http_port"))
		parse_sockaddr_in_list(&Config.Sockaddr.http);
#if USE_SSL
	else if (!strcmp(token, "https_port"))
		parse_https_port_list(&Config.Sockaddr.https);
#endif
#if USE_SSL
	else if (!strcmp(token, "ssl_unclean_shutdown"))
		parse_onoff(&Config.SSL.unclean_shutdown);
#endif
	else if (!strcmp(token, "icp_port"))
		parse_ushort(&Config.Port.icp);
#if USE_HTCP
	else if (!strcmp(token, "htcp_port"))
		parse_ushort(&Config.Port.htcp);
#endif
	else if (!strcmp(token, "mcast_groups"))
		parse_wordlist(&Config.mcast_group_list);
	else if (!strcmp(token, "udp_incoming_address"))
		parse_address(&Config.Addrs.udp_incoming);
	else if (!strcmp(token, "udp_outgoing_address"))
		parse_address(&Config.Addrs.udp_outgoing);
	else if (!strcmp(token, "cache_peer"))
		parse_peer(&Config.peers);
	else if (!strcmp(token, "cache_peer_domain"))
		parse_hostdomain();
	else if (!strcmp(token, "neighbor_type_domain"))
		parse_hostdomaintype();
	else if (!strcmp(token, "icp_query_timeout"))
		parse_int(&Config.Timeout.icp_query);
	else if (!strcmp(token, "maximum_icp_query_timeout"))
		parse_int(&Config.Timeout.icp_query_max);
	else if (!strcmp(token, "mcast_icp_query_timeout"))
		parse_int(&Config.Timeout.mcast_icp_query);
	else if (!strcmp(token, "dead_peer_timeout"))
		parse_time_t(&Config.Timeout.deadPeer);
	else if (!strcmp(token, "hierarchy_stoplist"))
		parse_wordlist(&Config.hierarchy_stoplist);
	else if (!strcmp(token, "no_cache"))
		parse_acl_access(&Config.accessList.noCache);
	else if (!strcmp(token, "cache_mem"))
		parse_b_size_t(&Config.memMaxSize);
	else if (!strcmp(token, "cache_swap_low"))
		parse_int(&Config.Swap.lowWaterMark);
	else if (!strcmp(token, "cache_swap_high"))
		parse_int(&Config.Swap.highWaterMark);
	else if (!strcmp(token, "maximum_object_size"))
		parse_b_size_t(&Config.Store.maxObjectSize);
	else if (!strcmp(token, "minimum_object_size"))
		parse_b_size_t(&Config.Store.minObjectSize);
	else if (!strcmp(token, "maximum_object_size_in_memory"))
		parse_b_size_t(&Config.Store.maxInMemObjSize);
	else if (!strcmp(token, "ipcache_size"))
		parse_int(&Config.ipcache.size);
	else if (!strcmp(token, "ipcache_low"))
		parse_int(&Config.ipcache.low);
	else if (!strcmp(token, "ipcache_high"))
		parse_int(&Config.ipcache.high);
	else if (!strcmp(token, "fqdncache_size"))
		parse_int(&Config.fqdncache.size);
	else if (!strcmp(token, "cache_replacement_policy"))
		parse_removalpolicy(&Config.replPolicy);
	else if (!strcmp(token, "memory_replacement_policy"))
		parse_removalpolicy(&Config.memPolicy);
	else if (!strcmp(token, "cache_dir"))
		parse_cachedir(&Config.cacheSwap);
	else if (!strcmp(token, "cache_access_log"))
		parse_string(&Config.Log.access);
	else if (!strcmp(token, "cache_log"))
		parse_string(&Config.Log.log);
	else if (!strcmp(token, "cache_store_log"))
		parse_string(&Config.Log.store);
	else if (!strcmp(token, "cache_swap_log"))
		parse_string(&Config.Log.swap);
	else if (!strcmp(token, "emulate_httpd_log"))
		parse_onoff(&Config.onoff.common_log);
	else if (!strcmp(token, "log_ip_on_direct"))
		parse_onoff(&Config.onoff.log_ip_on_direct);
	else if (!strcmp(token, "mime_table"))
		parse_string(&Config.mimeTablePathname);
	else if (!strcmp(token, "log_mime_hdrs"))
		parse_onoff(&Config.onoff.log_mime_hdrs);
#if USE_USERAGENT_LOG
	else if (!strcmp(token, "useragent_log"))
		parse_string(&Config.Log.useragent);
#endif
#if USE_REFERER_LOG
	else if (!strcmp(token, "referer_log"))
		parse_string(&Config.Log.referer);
#endif
	else if (!strcmp(token, "pid_filename"))
		parse_string(&Config.pidFilename);
	else if (!strcmp(token, "debug_options"))
		parse_eol(&Config.debugOptions);
	else if (!strcmp(token, "log_fqdn"))
		parse_onoff(&Config.onoff.log_fqdn);
	else if (!strcmp(token, "client_netmask"))
		parse_address(&Config.Addrs.client_netmask);
	else if (!strcmp(token, "ftp_user"))
		parse_string(&Config.Ftp.anon_user);
	else if (!strcmp(token, "ftp_list_width"))
		parse_size_t(&Config.Ftp.list_width);
	else if (!strcmp(token, "ftp_passive"))
		parse_onoff(&Config.Ftp.passive);
	else if (!strcmp(token, "ftp_sanitycheck"))
		parse_onoff(&Config.Ftp.sanitycheck);
#if USE_DNSSERVERS
	else if (!strcmp(token, "cache_dns_program"))
		parse_string(&Config.Program.dnsserver);
#endif
#if USE_DNSSERVERS
	else if (!strcmp(token, "dns_children"))
		parse_int(&Config.dnsChildren);
#endif
#if !USE_DNSSERVERS
	else if (!strcmp(token, "dns_retransmit_interval"))
		parse_time_t(&Config.Timeout.idns_retransmit);
#endif
#if !USE_DNSSERVERS
	else if (!strcmp(token, "dns_timeout"))
		parse_time_t(&Config.Timeout.idns_query);
#endif
#if USE_DNSSERVERS
	else if (!strcmp(token, "dns_defnames"))
		parse_onoff(&Config.onoff.res_defnames);
#endif
	else if (!strcmp(token, "dns_nameservers"))
		parse_wordlist(&Config.dns_nameservers);
	else if (!strcmp(token, "hosts_file"))
		parse_string(&Config.etcHostsPath);
	else if (!strcmp(token, "diskd_program"))
		parse_string(&Config.Program.diskd);
#if USE_UNLINKD
	else if (!strcmp(token, "unlinkd_program"))
		parse_string(&Config.Program.unlinkd);
#endif
#if USE_ICMP
	else if (!strcmp(token, "pinger_program"))
		parse_string(&Config.Program.pinger);
#endif
	else if (!strcmp(token, "redirect_program"))
		parse_wordlist(&Config.Program.redirect);
	else if (!strcmp(token, "redirect_children"))
		parse_int(&Config.redirectChildren);
	else if (!strcmp(token, "redirect_rewrites_host_header"))
		parse_onoff(&Config.onoff.redir_rewrites_host);
	else if (!strcmp(token, "redirector_access"))
		parse_acl_access(&Config.accessList.redirector);
	else if (!strcmp(token, "auth_param"))
		parse_authparam(&Config.authConfig);
	else if (!strcmp(token, "authenticate_cache_garbage_interval"))
		parse_time_t(&Config.authenticateGCInterval);
	else if (!strcmp(token, "authenticate_ttl"))
		parse_time_t(&Config.authenticateTTL);
	else if (!strcmp(token, "authenticate_ip_ttl"))
		parse_time_t(&Config.authenticateIpTTL);
	else if (!strcmp(token, "external_acl_type"))
		parse_externalAclHelper(&Config.externalAclHelperList);
	else if (!strcmp(token, "wais_relay_host"))
		parse_string(&Config.Wais.relayHost);
	else if (!strcmp(token, "wais_relay_port"))
		parse_ushort(&Config.Wais.relayPort);
	else if (!strcmp(token, "request_header_max_size"))
		parse_b_size_t(&Config.maxRequestHeaderSize);
	else if (!strcmp(token, "request_body_max_size"))
		parse_b_size_t(&Config.maxRequestBodySize);
	else if (!strcmp(token, "refresh_pattern"))
		parse_refreshpattern(&Config.Refresh);
	else if (!strcmp(token, "quick_abort_min"))
		parse_kb_size_t(&Config.quickAbort.min);
	else if (!strcmp(token, "quick_abort_max"))
		parse_kb_size_t(&Config.quickAbort.max);
	else if (!strcmp(token, "quick_abort_pct"))
		parse_int(&Config.quickAbort.pct);
	else if (!strcmp(token, "negative_ttl"))
		parse_time_t(&Config.negativeTtl);
	else if (!strcmp(token, "positive_dns_ttl"))
		parse_time_t(&Config.positiveDnsTtl);
	else if (!strcmp(token, "negative_dns_ttl"))
		parse_time_t(&Config.negativeDnsTtl);
	else if (!strcmp(token, "range_offset_limit"))
		parse_b_size_t(&Config.rangeOffsetLimit);
	else if (!strcmp(token, "connect_timeout"))
		parse_time_t(&Config.Timeout.connect);
	else if (!strcmp(token, "peer_connect_timeout"))
		parse_time_t(&Config.Timeout.peer_connect);
	else if (!strcmp(token, "read_timeout"))
		parse_time_t(&Config.Timeout.read);
	else if (!strcmp(token, "request_timeout"))
		parse_time_t(&Config.Timeout.request);
	else if (!strcmp(token, "persistent_request_timeout"))
		parse_time_t(&Config.Timeout.persistent_request);
	else if (!strcmp(token, "client_lifetime"))
		parse_time_t(&Config.Timeout.lifetime);
	else if (!strcmp(token, "half_closed_clients"))
		parse_onoff(&Config.onoff.half_closed_clients);
	else if (!strcmp(token, "pconn_timeout"))
		parse_time_t(&Config.Timeout.pconn);
#if USE_IDENT
	else if (!strcmp(token, "ident_timeout"))
		parse_time_t(&Config.Timeout.ident);
#endif
	else if (!strcmp(token, "shutdown_lifetime"))
		parse_time_t(&Config.shutdownLifetime);
	else if (!strcmp(token, "acl"))
		parse_acl(&Config.aclList);
	else if (!strcmp(token, "http_access"))
		parse_acl_access(&Config.accessList.http);
	else if (!strcmp(token, "http_reply_access"))
		parse_acl_access(&Config.accessList.reply);
	else if (!strcmp(token, "icp_access"))
		parse_acl_access(&Config.accessList.icp);
	else if (!strcmp(token, "miss_access"))
		parse_acl_access(&Config.accessList.miss);
	else if (!strcmp(token, "cache_peer_access"))
		parse_peer_access();
#if USE_IDENT
	else if (!strcmp(token, "ident_lookup_access"))
		parse_acl_access(&Config.accessList.identLookup);
#endif
	else if (!strcmp(token, "tcp_outgoing_tos"))
		parse_acl_tos(&Config.accessList.outgoing_tos);
	else if (!strcmp(token, "tcp_outgoing_address"))
		parse_acl_address(&Config.accessList.outgoing_address);
	else if (!strcmp(token, "reply_body_max_size"))
		parse_body_size_t(&Config.ReplyBodySize);
	else if (!strcmp(token, "cache_mgr"))
		parse_string(&Config.adminEmail);
	else if (!strcmp(token, "cache_effective_user"))
		parse_string(&Config.effectiveUser);
	else if (!strcmp(token, "cache_effective_group"))
		parse_string(&Config.effectiveGroup);
	else if (!strcmp(token, "visible_hostname"))
		parse_string(&Config.visibleHostname);
	else if (!strcmp(token, "unique_hostname"))
		parse_string(&Config.uniqueHostname);
	else if (!strcmp(token, "hostname_aliases"))
		parse_wordlist(&Config.hostnameAliases);
	else if (!strcmp(token, "announce_period"))
		parse_time_t(&Config.Announce.period);
	else if (!strcmp(token, "announce_host"))
		parse_string(&Config.Announce.host);
	else if (!strcmp(token, "announce_file"))
		parse_string(&Config.Announce.file);
	else if (!strcmp(token, "announce_port"))
		parse_ushort(&Config.Announce.port);
	else if (!strcmp(token, "httpd_accel_host"))
		parse_string(&Config.Accel.host);
	else if (!strcmp(token, "httpd_accel_port"))
		parse_ushort(&Config.Accel.port);
	else if (!strcmp(token, "httpd_accel_single_host"))
		parse_onoff(&Config.Accel.single_host);
	else if (!strcmp(token, "httpd_accel_with_proxy"))
		parse_onoff(&Config.onoff.accel_with_proxy);
	else if (!strcmp(token, "httpd_accel_uses_host_header"))
		parse_onoff(&opt_accel_uses_host);
	else if (!strcmp(token, "dns_testnames"))
		parse_wordlist(&Config.dns_testname_list);
	else if (!strcmp(token, "logfile_rotate"))
		parse_int(&Config.Log.rotateNumber);
	else if (!strcmp(token, "append_domain"))
		parse_string(&Config.appendDomain);
	else if (!strcmp(token, "tcp_recv_bufsize"))
		parse_b_size_t(&Config.tcpRcvBufsz);
	else if (!strcmp(token, "err_html_text"))
		parse_eol(&Config.errHtmlText);
	else if (!strcmp(token, "deny_info"))
		parse_denyinfo(&Config.denyInfoList);
	else if (!strcmp(token, "memory_pools"))
		parse_onoff(&Config.onoff.mem_pools);
	else if (!strcmp(token, "memory_pools_limit"))
		parse_b_size_t(&Config.MemPools.limit);
	else if (!strcmp(token, "forwarded_for"))
		parse_onoff(&opt_forwarded_for);
	else if (!strcmp(token, "log_icp_queries"))
		parse_onoff(&Config.onoff.log_udp);
	else if (!strcmp(token, "icp_hit_stale"))
		parse_onoff(&Config.onoff.icp_hit_stale);
	else if (!strcmp(token, "minimum_direct_hops"))
		parse_int(&Config.minDirectHops);
	else if (!strcmp(token, "minimum_direct_rtt"))
		parse_int(&Config.minDirectRtt);
	else if (!strcmp(token, "cachemgr_passwd"))
		parse_cachemgrpasswd(&Config.passwd_list);
	else if (!strcmp(token, "store_avg_object_size"))
		parse_kb_size_t(&Config.Store.avgObjectSize);
	else if (!strcmp(token, "store_objects_per_bucket"))
		parse_int(&Config.Store.objectsPerBucket);
	else if (!strcmp(token, "client_db"))
		parse_onoff(&Config.onoff.client_db);
	else if (!strcmp(token, "netdb_low"))
		parse_int(&Config.Netdb.low);
	else if (!strcmp(token, "netdb_high"))
		parse_int(&Config.Netdb.high);
	else if (!strcmp(token, "netdb_ping_period"))
		parse_time_t(&Config.Netdb.period);
	else if (!strcmp(token, "query_icmp"))
		parse_onoff(&Config.onoff.query_icmp);
	else if (!strcmp(token, "test_reachability"))
		parse_onoff(&Config.onoff.test_reachability);
	else if (!strcmp(token, "buffered_logs"))
		parse_onoff(&Config.onoff.buffered_logs);
#if HTTP_VIOLATIONS
	else if (!strcmp(token, "reload_into_ims"))
		parse_onoff(&Config.onoff.reload_into_ims);
#endif
	else if (!strcmp(token, "always_direct"))
		parse_acl_access(&Config.accessList.AlwaysDirect);
	else if (!strcmp(token, "never_direct"))
		parse_acl_access(&Config.accessList.NeverDirect);
#if HTTP_VIOLATIONS
	else if (!strcmp(token, "header_access"))
		parse_http_header_access[](&Config.header_access);
#endif
#if HTTP_VIOLATIONS
	else if (!strcmp(token, "header_replace"))
		parse_http_header_replace[](&Config.header_access);
#endif
	else if (!strcmp(token, "icon_directory"))
		parse_string(&Config.icons.directory);
	else if (!strcmp(token, "error_directory"))
		parse_string(&Config.errorDirectory);
	else if (!strcmp(token, "minimum_retry_timeout"))
		parse_time_t(&Config.retry.timeout);
	else if (!strcmp(token, "maximum_single_addr_tries"))
		parse_int(&Config.retry.maxtries);
#if SQUID_SNMP
	else if (!strcmp(token, "snmp_port"))
		parse_ushort(&Config.Port.snmp);
#endif
#if SQUID_SNMP
	else if (!strcmp(token, "snmp_access"))
		parse_acl_access(&Config.accessList.snmp);
#endif
#if SQUID_SNMP
	else if (!strcmp(token, "snmp_incoming_address"))
		parse_address(&Config.Addrs.snmp_incoming);
#endif
#if SQUID_SNMP
	else if (!strcmp(token, "snmp_outgoing_address"))
		parse_address(&Config.Addrs.snmp_outgoing);
#endif
	else if (!strcmp(token, "as_whois_server"))
		parse_string(&Config.as_whois_server);
#if USE_WCCP
	else if (!strcmp(token, "wccp_router"))
		parse_address(&Config.Wccp.router);
#endif
#if USE_WCCP
	else if (!strcmp(token, "wccp_version"))
		parse_int(&Config.Wccp.version);
#endif
#if USE_WCCP
	else if (!strcmp(token, "wccp_incoming_address"))
		parse_address(&Config.Wccp.incoming);
#endif
#if USE_WCCP
	else if (!strcmp(token, "wccp_outgoing_address"))
		parse_address(&Config.Wccp.outgoing);
#endif
#if DELAY_POOLS
	else if (!strcmp(token, "delay_pools"))
		parse_delay_pool_count(&Config.Delay);
#endif
#if DELAY_POOLS
	else if (!strcmp(token, "delay_class"))
		parse_delay_pool_class(&Config.Delay);
#endif
#if DELAY_POOLS
	else if (!strcmp(token, "delay_access"))
		parse_delay_pool_access(&Config.Delay);
#endif
#if DELAY_POOLS
	else if (!strcmp(token, "delay_parameters"))
		parse_delay_pool_rates(&Config.Delay);
#endif
#if DELAY_POOLS
	else if (!strcmp(token, "delay_initial_bucket_level"))
		parse_ushort(&Config.Delay.initial);
#endif
	else if (!strcmp(token, "incoming_icp_average"))
		parse_int(&Config.comm_incoming.icp_average);
	else if (!strcmp(token, "incoming_http_average"))
		parse_int(&Config.comm_incoming.http_average);
	else if (!strcmp(token, "incoming_dns_average"))
		parse_int(&Config.comm_incoming.dns_average);
	else if (!strcmp(token, "min_icp_poll_cnt"))
		parse_int(&Config.comm_incoming.icp_min_poll);
	else if (!strcmp(token, "min_dns_poll_cnt"))
		parse_int(&Config.comm_incoming.dns_min_poll);
	else if (!strcmp(token, "min_http_poll_cnt"))
		parse_int(&Config.comm_incoming.http_min_poll);
	else if (!strcmp(token, "max_open_disk_fds"))
		parse_int(&Config.max_open_disk_fds);
	else if (!strcmp(token, "offline_mode"))
		parse_onoff(&Config.onoff.offline);
	else if (!strcmp(token, "uri_whitespace"))
		parse_uri_whitespace(&Config.uri_whitespace);
	else if (!strcmp(token, "broken_posts"))
		parse_acl_access(&Config.accessList.brokenPosts);
#if MULTICAST_MISS_STREAM
	else if (!strcmp(token, "mcast_miss_addr"))
		parse_address(&Config.mcast_miss.addr);
#endif
#if MULTICAST_MISS_TTL
	else if (!strcmp(token, "mcast_miss_ttl"))
		parse_ushort(&Config.mcast_miss.ttl);
#endif
#if MULTICAST_MISS_STREAM
	else if (!strcmp(token, "mcast_miss_port"))
		parse_ushort(&Config.mcast_miss.port);
#endif
#if MULTICAST_MISS_STREAM
	else if (!strcmp(token, "mcast_miss_encode_key"))
		parse_string(&Config.mcast_miss.encode_key);
#endif
	else if (!strcmp(token, "nonhierarchical_direct"))
		parse_onoff(&Config.onoff.nonhierarchical_direct);
	else if (!strcmp(token, "prefer_direct"))
		parse_onoff(&Config.onoff.prefer_direct);
	else if (!strcmp(token, "strip_query_terms"))
		parse_onoff(&Config.onoff.strip_query_terms);
	else if (!strcmp(token, "coredump_dir"))
		parse_string(&Config.coredump_dir);
	else if (!strcmp(token, "redirector_bypass"))
		parse_onoff(&Config.onoff.redirector_bypass);
	else if (!strcmp(token, "ignore_unknown_nameservers"))
		parse_onoff(&Config.onoff.ignore_unknown_nameservers);
#if USE_CACHE_DIGESTS
	else if (!strcmp(token, "digest_generation"))
		parse_onoff(&Config.onoff.digest_generation);
#endif
#if USE_CACHE_DIGESTS
	else if (!strcmp(token, "digest_bits_per_entry"))
		parse_int(&Config.digest.bits_per_entry);
#endif
#if USE_CACHE_DIGESTS
	else if (!strcmp(token, "digest_rebuild_period"))
		parse_time_t(&Config.digest.rebuild_period);
#endif
#if USE_CACHE_DIGESTS
	else if (!strcmp(token, "digest_rewrite_period"))
		parse_time_t(&Config.digest.rewrite_period);
#endif
#if USE_CACHE_DIGESTS
	else if (!strcmp(token, "digest_swapout_chunk_size"))
		parse_b_size_t(&Config.digest.swapout_chunk_size);
#endif
#if USE_CACHE_DIGESTS
	else if (!strcmp(token, "digest_rebuild_chunk_percentage"))
		parse_int(&Config.digest.rebuild_chunk_percentage);
#endif
	else if (!strcmp(token, "chroot"))
		parse_string(&Config.chroot_dir);
	else if (!strcmp(token, "client_persistent_connections"))
		parse_onoff(&Config.onoff.client_pconns);
	else if (!strcmp(token, "server_persistent_connections"))
		parse_onoff(&Config.onoff.server_pconns);
	else if (!strcmp(token, "pipeline_prefetch"))
		parse_onoff(&Config.onoff.pipeline_prefetch);
	else if (!strcmp(token, "extension_methods"))
		parse_wordlist(&Config.ext_methods);
	else if (!strcmp(token, "request_entities"))
		parse_onoff(&Config.onoff.request_entities);
	else if (!strcmp(token, "high_response_time_warning"))
		parse_int(&Config.warnings.high_rptm);
	else if (!strcmp(token, "high_page_fault_warning"))
		parse_int(&Config.warnings.high_pf);
	else if (!strcmp(token, "high_memory_warning"))
		parse_b_size_t(&Config.warnings.high_memory);
	else if (!strcmp(token, "store_dir_select_algorithm"))
		parse_string(&Config.store_dir_select_algorithm);
#if WIP_FWD_LOG
	else if (!strcmp(token, "forward_log"))
		parse_string(&Config.Log.forward);
#endif
	else if (!strcmp(token, "ie_refresh"))
		parse_onoff(&Config.onoff.ie_refresh);
	else if (!strcmp(token, "vary_ignore_expire"))
		parse_onoff(&Config.onoff.vary_ignore_expire);
	else if (!strcmp(token, "sleep_after_fork"))
		parse_int(&Config.sleep_after_fork);
	else
		result = 0; /* failure */
	return(result);
}

static void
dump_config(StoreEntry *entry)
{
	dump_sockaddr_in_list(entry, "http_port", Config.Sockaddr.http);
#if USE_SSL
	dump_https_port_list(entry, "https_port", Config.Sockaddr.https);
#endif
#if USE_SSL
	dump_onoff(entry, "ssl_unclean_shutdown", Config.SSL.unclean_shutdown);
#endif
	dump_ushort(entry, "icp_port", Config.Port.icp);
#if USE_HTCP
	dump_ushort(entry, "htcp_port", Config.Port.htcp);
#endif
	dump_wordlist(entry, "mcast_groups", Config.mcast_group_list);
	dump_address(entry, "udp_incoming_address", Config.Addrs.udp_incoming);
	dump_address(entry, "udp_outgoing_address", Config.Addrs.udp_outgoing);
	dump_peer(entry, "cache_peer", Config.peers);
	dump_int(entry, "icp_query_timeout", Config.Timeout.icp_query);
	dump_int(entry, "maximum_icp_query_timeout", Config.Timeout.icp_query_max);
	dump_int(entry, "mcast_icp_query_timeout", Config.Timeout.mcast_icp_query);
	dump_time_t(entry, "dead_peer_timeout", Config.Timeout.deadPeer);
	dump_wordlist(entry, "hierarchy_stoplist", Config.hierarchy_stoplist);
	dump_acl_access(entry, "no_cache", Config.accessList.noCache);
	dump_b_size_t(entry, "cache_mem", Config.memMaxSize);
	dump_int(entry, "cache_swap_low", Config.Swap.lowWaterMark);
	dump_int(entry, "cache_swap_high", Config.Swap.highWaterMark);
	dump_b_size_t(entry, "maximum_object_size", Config.Store.maxObjectSize);
	dump_b_size_t(entry, "minimum_object_size", Config.Store.minObjectSize);
	dump_b_size_t(entry, "maximum_object_size_in_memory", Config.Store.maxInMemObjSize);
	dump_int(entry, "ipcache_size", Config.ipcache.size);
	dump_int(entry, "ipcache_low", Config.ipcache.low);
	dump_int(entry, "ipcache_high", Config.ipcache.high);
	dump_int(entry, "fqdncache_size", Config.fqdncache.size);
	dump_removalpolicy(entry, "cache_replacement_policy", Config.replPolicy);
	dump_removalpolicy(entry, "memory_replacement_policy", Config.memPolicy);
	dump_cachedir(entry, "cache_dir", Config.cacheSwap);
	dump_string(entry, "cache_access_log", Config.Log.access);
	dump_string(entry, "cache_log", Config.Log.log);
	dump_string(entry, "cache_store_log", Config.Log.store);
	dump_string(entry, "cache_swap_log", Config.Log.swap);
	dump_onoff(entry, "emulate_httpd_log", Config.onoff.common_log);
	dump_onoff(entry, "log_ip_on_direct", Config.onoff.log_ip_on_direct);
	dump_string(entry, "mime_table", Config.mimeTablePathname);
	dump_onoff(entry, "log_mime_hdrs", Config.onoff.log_mime_hdrs);
#if USE_USERAGENT_LOG
	dump_string(entry, "useragent_log", Config.Log.useragent);
#endif
#if USE_REFERER_LOG
	dump_string(entry, "referer_log", Config.Log.referer);
#endif
	dump_string(entry, "pid_filename", Config.pidFilename);
	dump_eol(entry, "debug_options", Config.debugOptions);
	dump_onoff(entry, "log_fqdn", Config.onoff.log_fqdn);
	dump_address(entry, "client_netmask", Config.Addrs.client_netmask);
	dump_string(entry, "ftp_user", Config.Ftp.anon_user);
	dump_size_t(entry, "ftp_list_width", Config.Ftp.list_width);
	dump_onoff(entry, "ftp_passive", Config.Ftp.passive);
	dump_onoff(entry, "ftp_sanitycheck", Config.Ftp.sanitycheck);
#if USE_DNSSERVERS
	dump_string(entry, "cache_dns_program", Config.Program.dnsserver);
#endif
#if USE_DNSSERVERS
	dump_int(entry, "dns_children", Config.dnsChildren);
#endif
#if !USE_DNSSERVERS
	dump_time_t(entry, "dns_retransmit_interval", Config.Timeout.idns_retransmit);
#endif
#if !USE_DNSSERVERS
	dump_time_t(entry, "dns_timeout", Config.Timeout.idns_query);
#endif
#if USE_DNSSERVERS
	dump_onoff(entry, "dns_defnames", Config.onoff.res_defnames);
#endif
	dump_wordlist(entry, "dns_nameservers", Config.dns_nameservers);
	dump_string(entry, "hosts_file", Config.etcHostsPath);
	dump_string(entry, "diskd_program", Config.Program.diskd);
#if USE_UNLINKD
	dump_string(entry, "unlinkd_program", Config.Program.unlinkd);
#endif
#if USE_ICMP
	dump_string(entry, "pinger_program", Config.Program.pinger);
#endif
	dump_wordlist(entry, "redirect_program", Config.Program.redirect);
	dump_int(entry, "redirect_children", Config.redirectChildren);
	dump_onoff(entry, "redirect_rewrites_host_header", Config.onoff.redir_rewrites_host);
	dump_acl_access(entry, "redirector_access", Config.accessList.redirector);
	dump_authparam(entry, "auth_param", Config.authConfig);
	dump_time_t(entry, "authenticate_cache_garbage_interval", Config.authenticateGCInterval);
	dump_time_t(entry, "authenticate_ttl", Config.authenticateTTL);
	dump_time_t(entry, "authenticate_ip_ttl", Config.authenticateIpTTL);
	dump_externalAclHelper(entry, "external_acl_type", Config.externalAclHelperList);
	dump_string(entry, "wais_relay_host", Config.Wais.relayHost);
	dump_ushort(entry, "wais_relay_port", Config.Wais.relayPort);
	dump_b_size_t(entry, "request_header_max_size", Config.maxRequestHeaderSize);
	dump_b_size_t(entry, "request_body_max_size", Config.maxRequestBodySize);
	dump_refreshpattern(entry, "refresh_pattern", Config.Refresh);
	dump_kb_size_t(entry, "quick_abort_min", Config.quickAbort.min);
	dump_kb_size_t(entry, "quick_abort_max", Config.quickAbort.max);
	dump_int(entry, "quick_abort_pct", Config.quickAbort.pct);
	dump_time_t(entry, "negative_ttl", Config.negativeTtl);
	dump_time_t(entry, "positive_dns_ttl", Config.positiveDnsTtl);
	dump_time_t(entry, "negative_dns_ttl", Config.negativeDnsTtl);
	dump_b_size_t(entry, "range_offset_limit", Config.rangeOffsetLimit);
	dump_time_t(entry, "connect_timeout", Config.Timeout.connect);
	dump_time_t(entry, "peer_connect_timeout", Config.Timeout.peer_connect);
	dump_time_t(entry, "read_timeout", Config.Timeout.read);
	dump_time_t(entry, "request_timeout", Config.Timeout.request);
	dump_time_t(entry, "persistent_request_timeout", Config.Timeout.persistent_request);
	dump_time_t(entry, "client_lifetime", Config.Timeout.lifetime);
	dump_onoff(entry, "half_closed_clients", Config.onoff.half_closed_clients);
	dump_time_t(entry, "pconn_timeout", Config.Timeout.pconn);
#if USE_IDENT
	dump_time_t(entry, "ident_timeout", Config.Timeout.ident);
#endif
	dump_time_t(entry, "shutdown_lifetime", Config.shutdownLifetime);
	dump_acl(entry, "acl", Config.aclList);
	dump_acl_access(entry, "http_access", Config.accessList.http);
	dump_acl_access(entry, "http_reply_access", Config.accessList.reply);
	dump_acl_access(entry, "icp_access", Config.accessList.icp);
	dump_acl_access(entry, "miss_access", Config.accessList.miss);
#if USE_IDENT
	dump_acl_access(entry, "ident_lookup_access", Config.accessList.identLookup);
#endif
	dump_acl_tos(entry, "tcp_outgoing_tos", Config.accessList.outgoing_tos);
	dump_acl_address(entry, "tcp_outgoing_address", Config.accessList.outgoing_address);
	dump_body_size_t(entry, "reply_body_max_size", Config.ReplyBodySize);
	dump_string(entry, "cache_mgr", Config.adminEmail);
	dump_string(entry, "cache_effective_user", Config.effectiveUser);
	dump_string(entry, "cache_effective_group", Config.effectiveGroup);
	dump_string(entry, "visible_hostname", Config.visibleHostname);
	dump_string(entry, "unique_hostname", Config.uniqueHostname);
	dump_wordlist(entry, "hostname_aliases", Config.hostnameAliases);
	dump_time_t(entry, "announce_period", Config.Announce.period);
	dump_string(entry, "announce_host", Config.Announce.host);
	dump_string(entry, "announce_file", Config.Announce.file);
	dump_ushort(entry, "announce_port", Config.Announce.port);
	dump_string(entry, "httpd_accel_host", Config.Accel.host);
	dump_ushort(entry, "httpd_accel_port", Config.Accel.port);
	dump_onoff(entry, "httpd_accel_single_host", Config.Accel.single_host);
	dump_onoff(entry, "httpd_accel_with_proxy", Config.onoff.accel_with_proxy);
	dump_onoff(entry, "httpd_accel_uses_host_header", opt_accel_uses_host);
	dump_wordlist(entry, "dns_testnames", Config.dns_testname_list);
	dump_int(entry, "logfile_rotate", Config.Log.rotateNumber);
	dump_string(entry, "append_domain", Config.appendDomain);
	dump_b_size_t(entry, "tcp_recv_bufsize", Config.tcpRcvBufsz);
	dump_eol(entry, "err_html_text", Config.errHtmlText);
	dump_denyinfo(entry, "deny_info", Config.denyInfoList);
	dump_onoff(entry, "memory_pools", Config.onoff.mem_pools);
	dump_b_size_t(entry, "memory_pools_limit", Config.MemPools.limit);
	dump_onoff(entry, "forwarded_for", opt_forwarded_for);
	dump_onoff(entry, "log_icp_queries", Config.onoff.log_udp);
	dump_onoff(entry, "icp_hit_stale", Config.onoff.icp_hit_stale);
	dump_int(entry, "minimum_direct_hops", Config.minDirectHops);
	dump_int(entry, "minimum_direct_rtt", Config.minDirectRtt);
	dump_cachemgrpasswd(entry, "cachemgr_passwd", Config.passwd_list);
	dump_kb_size_t(entry, "store_avg_object_size", Config.Store.avgObjectSize);
	dump_int(entry, "store_objects_per_bucket", Config.Store.objectsPerBucket);
	dump_onoff(entry, "client_db", Config.onoff.client_db);
	dump_int(entry, "netdb_low", Config.Netdb.low);
	dump_int(entry, "netdb_high", Config.Netdb.high);
	dump_time_t(entry, "netdb_ping_period", Config.Netdb.period);
	dump_onoff(entry, "query_icmp", Config.onoff.query_icmp);
	dump_onoff(entry, "test_reachability", Config.onoff.test_reachability);
	dump_onoff(entry, "buffered_logs", Config.onoff.buffered_logs);
#if HTTP_VIOLATIONS
	dump_onoff(entry, "reload_into_ims", Config.onoff.reload_into_ims);
#endif
	dump_acl_access(entry, "always_direct", Config.accessList.AlwaysDirect);
	dump_acl_access(entry, "never_direct", Config.accessList.NeverDirect);
#if HTTP_VIOLATIONS
	dump_http_header_access[](entry, "header_access", Config.header_access);
#endif
#if HTTP_VIOLATIONS
	dump_http_header_replace[](entry, "header_replace", Config.header_access);
#endif
	dump_string(entry, "icon_directory", Config.icons.directory);
	dump_string(entry, "error_directory", Config.errorDirectory);
	dump_time_t(entry, "minimum_retry_timeout", Config.retry.timeout);
	dump_int(entry, "maximum_single_addr_tries", Config.retry.maxtries);
#if SQUID_SNMP
	dump_ushort(entry, "snmp_port", Config.Port.snmp);
#endif
#if SQUID_SNMP
	dump_acl_access(entry, "snmp_access", Config.accessList.snmp);
#endif
#if SQUID_SNMP
	dump_address(entry, "snmp_incoming_address", Config.Addrs.snmp_incoming);
#endif
#if SQUID_SNMP
	dump_address(entry, "snmp_outgoing_address", Config.Addrs.snmp_outgoing);
#endif
	dump_string(entry, "as_whois_server", Config.as_whois_server);
#if USE_WCCP
	dump_address(entry, "wccp_router", Config.Wccp.router);
#endif
#if USE_WCCP
	dump_int(entry, "wccp_version", Config.Wccp.version);
#endif
#if USE_WCCP
	dump_address(entry, "wccp_incoming_address", Config.Wccp.incoming);
#endif
#if USE_WCCP
	dump_address(entry, "wccp_outgoing_address", Config.Wccp.outgoing);
#endif
#if DELAY_POOLS
	dump_delay_pool_count(entry, "delay_pools", Config.Delay);
#endif
#if DELAY_POOLS
	dump_delay_pool_class(entry, "delay_class", Config.Delay);
#endif
#if DELAY_POOLS
	dump_delay_pool_access(entry, "delay_access", Config.Delay);
#endif
#if DELAY_POOLS
	dump_delay_pool_rates(entry, "delay_parameters", Config.Delay);
#endif
#if DELAY_POOLS
	dump_ushort(entry, "delay_initial_bucket_level", Config.Delay.initial);
#endif
	dump_int(entry, "incoming_icp_average", Config.comm_incoming.icp_average);
	dump_int(entry, "incoming_http_average", Config.comm_incoming.http_average);
	dump_int(entry, "incoming_dns_average", Config.comm_incoming.dns_average);
	dump_int(entry, "min_icp_poll_cnt", Config.comm_incoming.icp_min_poll);
	dump_int(entry, "min_dns_poll_cnt", Config.comm_incoming.dns_min_poll);
	dump_int(entry, "min_http_poll_cnt", Config.comm_incoming.http_min_poll);
	dump_int(entry, "max_open_disk_fds", Config.max_open_disk_fds);
	dump_onoff(entry, "offline_mode", Config.onoff.offline);
	dump_uri_whitespace(entry, "uri_whitespace", Config.uri_whitespace);
	dump_acl_access(entry, "broken_posts", Config.accessList.brokenPosts);
#if MULTICAST_MISS_STREAM
	dump_address(entry, "mcast_miss_addr", Config.mcast_miss.addr);
#endif
#if MULTICAST_MISS_TTL
	dump_ushort(entry, "mcast_miss_ttl", Config.mcast_miss.ttl);
#endif
#if MULTICAST_MISS_STREAM
	dump_ushort(entry, "mcast_miss_port", Config.mcast_miss.port);
#endif
#if MULTICAST_MISS_STREAM
	dump_string(entry, "mcast_miss_encode_key", Config.mcast_miss.encode_key);
#endif
	dump_onoff(entry, "nonhierarchical_direct", Config.onoff.nonhierarchical_direct);
	dump_onoff(entry, "prefer_direct", Config.onoff.prefer_direct);
	dump_onoff(entry, "strip_query_terms", Config.onoff.strip_query_terms);
	dump_string(entry, "coredump_dir", Config.coredump_dir);
	dump_onoff(entry, "redirector_bypass", Config.onoff.redirector_bypass);
	dump_onoff(entry, "ignore_unknown_nameservers", Config.onoff.ignore_unknown_nameservers);
#if USE_CACHE_DIGESTS
	dump_onoff(entry, "digest_generation", Config.onoff.digest_generation);
#endif
#if USE_CACHE_DIGESTS
	dump_int(entry, "digest_bits_per_entry", Config.digest.bits_per_entry);
#endif
#if USE_CACHE_DIGESTS
	dump_time_t(entry, "digest_rebuild_period", Config.digest.rebuild_period);
#endif
#if USE_CACHE_DIGESTS
	dump_time_t(entry, "digest_rewrite_period", Config.digest.rewrite_period);
#endif
#if USE_CACHE_DIGESTS
	dump_b_size_t(entry, "digest_swapout_chunk_size", Config.digest.swapout_chunk_size);
#endif
#if USE_CACHE_DIGESTS
	dump_int(entry, "digest_rebuild_chunk_percentage", Config.digest.rebuild_chunk_percentage);
#endif
	dump_string(entry, "chroot", Config.chroot_dir);
	dump_onoff(entry, "client_persistent_connections", Config.onoff.client_pconns);
	dump_onoff(entry, "server_persistent_connections", Config.onoff.server_pconns);
	dump_onoff(entry, "pipeline_prefetch", Config.onoff.pipeline_prefetch);
	dump_wordlist(entry, "extension_methods", Config.ext_methods);
	dump_onoff(entry, "request_entities", Config.onoff.request_entities);
	dump_int(entry, "high_response_time_warning", Config.warnings.high_rptm);
	dump_int(entry, "high_page_fault_warning", Config.warnings.high_pf);
	dump_b_size_t(entry, "high_memory_warning", Config.warnings.high_memory);
	dump_string(entry, "store_dir_select_algorithm", Config.store_dir_select_algorithm);
#if WIP_FWD_LOG
	dump_string(entry, "forward_log", Config.Log.forward);
#endif
	dump_onoff(entry, "ie_refresh", Config.onoff.ie_refresh);
	dump_onoff(entry, "vary_ignore_expire", Config.onoff.vary_ignore_expire);
	dump_int(entry, "sleep_after_fork", Config.sleep_after_fork);
}

static void
free_all(void)
{
	free_sockaddr_in_list(&Config.Sockaddr.http);
#if USE_SSL
	free_https_port_list(&Config.Sockaddr.https);
#endif
#if USE_SSL
	free_onoff(&Config.SSL.unclean_shutdown);
#endif
	free_ushort(&Config.Port.icp);
#if USE_HTCP
	free_ushort(&Config.Port.htcp);
#endif
	free_wordlist(&Config.mcast_group_list);
	free_address(&Config.Addrs.udp_incoming);
	free_address(&Config.Addrs.udp_outgoing);
	free_peer(&Config.peers);
	free_int(&Config.Timeout.icp_query);
	free_int(&Config.Timeout.icp_query_max);
	free_int(&Config.Timeout.mcast_icp_query);
	free_time_t(&Config.Timeout.deadPeer);
	free_wordlist(&Config.hierarchy_stoplist);
	free_acl_access(&Config.accessList.noCache);
	free_b_size_t(&Config.memMaxSize);
	free_int(&Config.Swap.lowWaterMark);
	free_int(&Config.Swap.highWaterMark);
	free_b_size_t(&Config.Store.maxObjectSize);
	free_b_size_t(&Config.Store.minObjectSize);
	free_b_size_t(&Config.Store.maxInMemObjSize);
	free_int(&Config.ipcache.size);
	free_int(&Config.ipcache.low);
	free_int(&Config.ipcache.high);
	free_int(&Config.fqdncache.size);
	free_removalpolicy(&Config.replPolicy);
	free_removalpolicy(&Config.memPolicy);
	free_cachedir(&Config.cacheSwap);
	free_string(&Config.Log.access);
	free_string(&Config.Log.log);
	free_string(&Config.Log.store);
	free_string(&Config.Log.swap);
	free_onoff(&Config.onoff.common_log);
	free_onoff(&Config.onoff.log_ip_on_direct);
	free_string(&Config.mimeTablePathname);
	free_onoff(&Config.onoff.log_mime_hdrs);
#if USE_USERAGENT_LOG
	free_string(&Config.Log.useragent);
#endif
#if USE_REFERER_LOG
	free_string(&Config.Log.referer);
#endif
	free_string(&Config.pidFilename);
	free_eol(&Config.debugOptions);
	free_onoff(&Config.onoff.log_fqdn);
	free_address(&Config.Addrs.client_netmask);
	free_string(&Config.Ftp.anon_user);
	free_size_t(&Config.Ftp.list_width);
	free_onoff(&Config.Ftp.passive);
	free_onoff(&Config.Ftp.sanitycheck);
#if USE_DNSSERVERS
	free_string(&Config.Program.dnsserver);
#endif
#if USE_DNSSERVERS
	free_int(&Config.dnsChildren);
#endif
#if !USE_DNSSERVERS
	free_time_t(&Config.Timeout.idns_retransmit);
#endif
#if !USE_DNSSERVERS
	free_time_t(&Config.Timeout.idns_query);
#endif
#if USE_DNSSERVERS
	free_onoff(&Config.onoff.res_defnames);
#endif
	free_wordlist(&Config.dns_nameservers);
	free_string(&Config.etcHostsPath);
	free_string(&Config.Program.diskd);
#if USE_UNLINKD
	free_string(&Config.Program.unlinkd);
#endif
#if USE_ICMP
	free_string(&Config.Program.pinger);
#endif
	free_wordlist(&Config.Program.redirect);
	free_int(&Config.redirectChildren);
	free_onoff(&Config.onoff.redir_rewrites_host);
	free_acl_access(&Config.accessList.redirector);
	free_authparam(&Config.authConfig);
	free_time_t(&Config.authenticateGCInterval);
	free_time_t(&Config.authenticateTTL);
	free_time_t(&Config.authenticateIpTTL);
	free_externalAclHelper(&Config.externalAclHelperList);
	free_string(&Config.Wais.relayHost);
	free_ushort(&Config.Wais.relayPort);
	free_b_size_t(&Config.maxRequestHeaderSize);
	free_b_size_t(&Config.maxRequestBodySize);
	free_refreshpattern(&Config.Refresh);
	free_kb_size_t(&Config.quickAbort.min);
	free_kb_size_t(&Config.quickAbort.max);
	free_int(&Config.quickAbort.pct);
	free_time_t(&Config.negativeTtl);
	free_time_t(&Config.positiveDnsTtl);
	free_time_t(&Config.negativeDnsTtl);
	free_b_size_t(&Config.rangeOffsetLimit);
	free_time_t(&Config.Timeout.connect);
	free_time_t(&Config.Timeout.peer_connect);
	free_time_t(&Config.Timeout.read);
	free_time_t(&Config.Timeout.request);
	free_time_t(&Config.Timeout.persistent_request);
	free_time_t(&Config.Timeout.lifetime);
	free_onoff(&Config.onoff.half_closed_clients);
	free_time_t(&Config.Timeout.pconn);
#if USE_IDENT
	free_time_t(&Config.Timeout.ident);
#endif
	free_time_t(&Config.shutdownLifetime);
	free_acl(&Config.aclList);
	free_acl_access(&Config.accessList.http);
	free_acl_access(&Config.accessList.reply);
	free_acl_access(&Config.accessList.icp);
	free_acl_access(&Config.accessList.miss);
#if USE_IDENT
	free_acl_access(&Config.accessList.identLookup);
#endif
	free_acl_tos(&Config.accessList.outgoing_tos);
	free_acl_address(&Config.accessList.outgoing_address);
	free_body_size_t(&Config.ReplyBodySize);
	free_string(&Config.adminEmail);
	free_string(&Config.effectiveUser);
	free_string(&Config.effectiveGroup);
	free_string(&Config.visibleHostname);
	free_string(&Config.uniqueHostname);
	free_wordlist(&Config.hostnameAliases);
	free_time_t(&Config.Announce.period);
	free_string(&Config.Announce.host);
	free_string(&Config.Announce.file);
	free_ushort(&Config.Announce.port);
	free_string(&Config.Accel.host);
	free_ushort(&Config.Accel.port);
	free_onoff(&Config.Accel.single_host);
	free_onoff(&Config.onoff.accel_with_proxy);
	free_onoff(&opt_accel_uses_host);
	free_wordlist(&Config.dns_testname_list);
	free_int(&Config.Log.rotateNumber);
	free_string(&Config.appendDomain);
	free_b_size_t(&Config.tcpRcvBufsz);
	free_eol(&Config.errHtmlText);
	free_denyinfo(&Config.denyInfoList);
	free_onoff(&Config.onoff.mem_pools);
	free_b_size_t(&Config.MemPools.limit);
	free_onoff(&opt_forwarded_for);
	free_onoff(&Config.onoff.log_udp);
	free_onoff(&Config.onoff.icp_hit_stale);
	free_int(&Config.minDirectHops);
	free_int(&Config.minDirectRtt);
	free_cachemgrpasswd(&Config.passwd_list);
	free_kb_size_t(&Config.Store.avgObjectSize);
	free_int(&Config.Store.objectsPerBucket);
	free_onoff(&Config.onoff.client_db);
	free_int(&Config.Netdb.low);
	free_int(&Config.Netdb.high);
	free_time_t(&Config.Netdb.period);
	free_onoff(&Config.onoff.query_icmp);
	free_onoff(&Config.onoff.test_reachability);
	free_onoff(&Config.onoff.buffered_logs);
#if HTTP_VIOLATIONS
	free_onoff(&Config.onoff.reload_into_ims);
#endif
	free_acl_access(&Config.accessList.AlwaysDirect);
	free_acl_access(&Config.accessList.NeverDirect);
#if HTTP_VIOLATIONS
	free_http_header_access[](&Config.header_access);
#endif
#if HTTP_VIOLATIONS
	free_http_header_replace[](&Config.header_access);
#endif
	free_string(&Config.icons.directory);
	free_string(&Config.errorDirectory);
	free_time_t(&Config.retry.timeout);
	free_int(&Config.retry.maxtries);
#if SQUID_SNMP
	free_ushort(&Config.Port.snmp);
#endif
#if SQUID_SNMP
	free_acl_access(&Config.accessList.snmp);
#endif
#if SQUID_SNMP
	free_address(&Config.Addrs.snmp_incoming);
#endif
#if SQUID_SNMP
	free_address(&Config.Addrs.snmp_outgoing);
#endif
	free_string(&Config.as_whois_server);
#if USE_WCCP
	free_address(&Config.Wccp.router);
#endif
#if USE_WCCP
	free_int(&Config.Wccp.version);
#endif
#if USE_WCCP
	free_address(&Config.Wccp.incoming);
#endif
#if USE_WCCP
	free_address(&Config.Wccp.outgoing);
#endif
#if DELAY_POOLS
	free_delay_pool_count(&Config.Delay);
#endif
#if DELAY_POOLS
	free_delay_pool_class(&Config.Delay);
#endif
#if DELAY_POOLS
	free_delay_pool_access(&Config.Delay);
#endif
#if DELAY_POOLS
	free_delay_pool_rates(&Config.Delay);
#endif
#if DELAY_POOLS
	free_ushort(&Config.Delay.initial);
#endif
	free_int(&Config.comm_incoming.icp_average);
	free_int(&Config.comm_incoming.http_average);
	free_int(&Config.comm_incoming.dns_average);
	free_int(&Config.comm_incoming.icp_min_poll);
	free_int(&Config.comm_incoming.dns_min_poll);
	free_int(&Config.comm_incoming.http_min_poll);
	free_int(&Config.max_open_disk_fds);
	free_onoff(&Config.onoff.offline);
	free_uri_whitespace(&Config.uri_whitespace);
	free_acl_access(&Config.accessList.brokenPosts);
#if MULTICAST_MISS_STREAM
	free_address(&Config.mcast_miss.addr);
#endif
#if MULTICAST_MISS_TTL
	free_ushort(&Config.mcast_miss.ttl);
#endif
#if MULTICAST_MISS_STREAM
	free_ushort(&Config.mcast_miss.port);
#endif
#if MULTICAST_MISS_STREAM
	free_string(&Config.mcast_miss.encode_key);
#endif
	free_onoff(&Config.onoff.nonhierarchical_direct);
	free_onoff(&Config.onoff.prefer_direct);
	free_onoff(&Config.onoff.strip_query_terms);
	free_string(&Config.coredump_dir);
	free_onoff(&Config.onoff.redirector_bypass);
	free_onoff(&Config.onoff.ignore_unknown_nameservers);
#if USE_CACHE_DIGESTS
	free_onoff(&Config.onoff.digest_generation);
#endif
#if USE_CACHE_DIGESTS
	free_int(&Config.digest.bits_per_entry);
#endif
#if USE_CACHE_DIGESTS
	free_time_t(&Config.digest.rebuild_period);
#endif
#if USE_CACHE_DIGESTS
	free_time_t(&Config.digest.rewrite_period);
#endif
#if USE_CACHE_DIGESTS
	free_b_size_t(&Config.digest.swapout_chunk_size);
#endif
#if USE_CACHE_DIGESTS
	free_int(&Config.digest.rebuild_chunk_percentage);
#endif
	free_string(&Config.chroot_dir);
	free_onoff(&Config.onoff.client_pconns);
	free_onoff(&Config.onoff.server_pconns);
	free_onoff(&Config.onoff.pipeline_prefetch);
	free_wordlist(&Config.ext_methods);
	free_onoff(&Config.onoff.request_entities);
	free_int(&Config.warnings.high_rptm);
	free_int(&Config.warnings.high_pf);
	free_b_size_t(&Config.warnings.high_memory);
	free_string(&Config.store_dir_select_algorithm);
#if WIP_FWD_LOG
	free_string(&Config.Log.forward);
#endif
	free_onoff(&Config.onoff.ie_refresh);
	free_onoff(&Config.onoff.vary_ignore_expire);
	free_int(&Config.sleep_after_fork);
}


include $(top_srcdir)/Make_global.am

YACC=@YACC@ -d

CLEANFILES = read_config_yy.c read_config_lex.c

sbin_PROGRAMS = conntrack conntrackd

conntrack_SOURCES = conntrack.c
conntrack_LDADD = ../extensions/libct_proto_tcp.la ../extensions/libct_proto_udp.la ../extensions/libct_proto_icmp.la

conntrackd_SOURCES = alarm.c main.c run.c hash.c buffer.c \
		    local.c log.c mcast.c netlink.c \
		    ignore_pool.c \
		    cache.c cache_iterators.c \
		    cache_lifetime.c cache_timer.c \
		    sync-mode.c sync-notrack.c sync-nack.c \
		    traffic_stats.c stats-mode.c \
		    network.c \
		    state_helper.c state_helper_tcp.c \
		    timer.c \
		    build.c parse.c \
		    read_config_yy.y read_config_lex.l

conntrackd_LDFLAGS = $(all_libraries) -lnfnetlink -lnetfilter_conntrack

EXTRA_DIST = read_config_yy.h

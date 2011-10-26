include $(top_srcdir)/Make_global.am

noinst_PROGRAMS = expect_dump expect_create expect_get expect_delete \
	       expect_flush expect_events \
	       conntrack_create conntrack_dump conntrack_update \
	       conntrack_delete conntrack_flush conntrack_create_nat \
	       conntrack_get conntrack_events

conntrack_create_SOURCES = conntrack_create.c
conntrack_create_LDADD = ../src/libnetfilter_conntrack.la
conntrack_create_LDFLAGS = -dynamic -ldl

conntrack_get_SOURCES = conntrack_get.c
conntrack_get_LDADD = ../src/libnetfilter_conntrack.la
conntrack_get_LDFLAGS = -dynamic -ldl

conntrack_create_nat_SOURCES = conntrack_create_nat.c
conntrack_create_nat_LDADD = ../src/libnetfilter_conntrack.la
conntrack_create_nat_LDFLAGS = -dynamic -ldl

conntrack_update_SOURCES = conntrack_update.c
conntrack_update_LDADD = ../src/libnetfilter_conntrack.la
conntrack_update_LDFLAGS = -dynamic -ldl

conntrack_delete_SOURCES = conntrack_delete.c
conntrack_delete_LDADD = ../src/libnetfilter_conntrack.la
conntrack_delete_LDFLAGS = -dynamic -ldl

conntrack_dump_SOURCES = conntrack_dump.c
conntrack_dump_LDADD = ../src/libnetfilter_conntrack.la
conntrack_dump_LDFLAGS = -dynamic -ldl

conntrack_flush_SOURCES = conntrack_flush.c
conntrack_flush_LDADD = ../src/libnetfilter_conntrack.la
conntrack_flush_LDFLAGS = -dynamic -ldl

conntrack_events_SOURCES = conntrack_events.c
conntrack_events_LDADD = ../src/libnetfilter_conntrack.la
conntrack_events_LDFLAGS = -dynamic -ldl

expect_dump_SOURCES = expect_dump.c
expect_dump_LDADD = ../src/libnetfilter_conntrack.la
expect_dump_LDFLAGS = -dynamic -ldl

expect_create_SOURCES = expect_create.c
expect_create_LDADD = ../src/libnetfilter_conntrack.la
expect_create_LDFLAGS = -dynamic -ldl

expect_get_SOURCES = expect_get.c
expect_get_LDADD = ../src/libnetfilter_conntrack.la
expect_get_LDFLAGS = -dynamic -ldl

expect_delete_SOURCES = expect_delete.c
expect_delete_LDADD = ../src/libnetfilter_conntrack.la
expect_delete_LDFLAGS = -dynamic -ldl

expect_flush_SOURCES = expect_flush.c
expect_flush_LDADD = ../src/libnetfilter_conntrack.la
expect_flush_LDFLAGS = -dynamic -ldl

expect_events_SOURCES = expect_events.c
expect_events_LDADD = ../src/libnetfilter_conntrack.la
expect_events_LDFLAGS = -dynamic -ldl

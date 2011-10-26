SUBDIRS = portscan int-snort

noinst_LIBRARIES = libflow.a

libflow_a_SOURCES = common_defs.h \
                    flow.c flow.h \
                    flow_cache.c flow_cache.h \
                    flow_callback.c flow_callback.h \
                    flow_class.c flow_class.h \
                    flow_config.h \
                    flow_error.h \
                    flow_stat.c flow_stat.h \
                    flow_hash.c flow_hash.h \
                    flow_print.c flow_print.h

INCLUDES = @INCLUDES@

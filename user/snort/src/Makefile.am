## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies

bin_PROGRAMS = snort

snort_SOURCES = cdefs.h \
event.h \
fatal.h \
generators.h \
prototypes.h \
plugin_enum.h \
rules.h \
sys_include.h \
checksum.h \
codes.c codes.h \
debug.c debug.h \
decode.c decode.h \
log.c log.h \
mstring.c mstring.h \
parser.c parser.h \
profiler.c profiler.h \
plugbase.c plugbase.h \
preprocids.h \
snort.c snort.h \
build.h \
snprintf.c snprintf.h \
strlcatu.c strlcatu.h \
strlcpyu.c strlcpyu.h \
tag.c tag.h \
ubi_BinTree.c ubi_BinTree.h \
ubi_SplayTree.c ubi_SplayTree.h \
util.c util.h \
detect.c detect.h \
signature.c signature.h \
mempool.c mempool.h \
sf_sdlist.c sf_sdlist.h \
fpcreate.c fpcreate.h \
fpdetect.c fpdetect.h \
pcrm.c pcrm.h \
bounds.h \
byte_extract.c \
byte_extract.h \
timersub.h \
spo_plugbase.h \
sfthreshold.c sfthreshold.h \
packet_time.c packet_time.h \
event_wrapper.c event_wrapper.h \
smalloc.h \
snort_packet_header.h \
event_queue.c event_queue.h \
inline.c inline.h ipv6.c ipv6.h

snort_LDADD = output-plugins/libspo.a \
detection-plugins/libspd.a            \
dynamic-plugins/libdynamic.a            \
preprocessors/libspp.a                \
preprocessors/flow/portscan/libportscan.a \
preprocessors/flow/libflow.a \
parser/libparser.a \
preprocessors/HttpInspect/libhttp_inspect.a \
preprocessors/Stream5/libstream5.a \
sfutil/libsfutil.a

EXAMPLES_DIR = dynamic-examples

SUBDIRS = sfutil win32 output-plugins detection-plugins dynamic-plugins preprocessors parser dynamic-preprocessors $(EXAMPLES_DIR)

INCLUDES = @INCLUDES@

SUBDIRS = . tests

AM_CPPFLAGS= \
	-I ${top_srcdir}/libutil \
	-I ${top_srcdir}/libop
AM_CXXFLAGS = @OP_CXXFLAGS@

noinst_LIBRARIES = libutil++.a
libutil___a_SOURCES = \
	op_bfd.cpp \
	op_bfd.h \
	bfd_support.cpp \
	bfd_support.h \
	string_filter.cpp \
	string_filter.h \
	glob_filter.cpp \
	glob_filter.h \
	growable_vector.h \
	path_filter.cpp \
	path_filter.h \
	file_manip.cpp \
	file_manip.h \
	stream_util.cpp \
	stream_util.h \
	string_manip.cpp \
	string_manip.h \
	cverb.cpp \
	cverb.h \
	generic_spec.h \
	op_exception.cpp \
	op_exception.h \
	child_reader.cpp \
	child_reader.h \
	unique_storage.h \
	utility.h \
	cached_value.h \
	comma_list.h

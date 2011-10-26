AM_CPPFLAGS = \
	-I ${top_srcdir}/libutil++ \
	-I ${top_srcdir}/libregex

AM_CXXFLAGS = @OP_CXXFLAGS@

check_PROGRAMS = regex_test

regex_test_SOURCES = regex_test.cpp
regex_test_LDADD = \
	../libop_regex.a \
	../../libutil++/libutil++.a

EXTRA_DIST = mangled-name.in

TESTS = ${check_PROGRAMS}

# This script was automatically generated from the dsa-1087
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several encoding problems have been discovered in PostgreSQL, a
popular SQL database.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling
    of invalidly-encoded multibyte text data which could allow an
    attacker to inject arbitrary SQL commands.
    A similar problem exists in client-side encodings (such as SJIS,
    BIG5, GBK, GB18030, and UHC) which contain valid multibyte
    characters that end with the backslash character.  An attacker
    could supply a specially crafted byte sequence that is able to
    inject arbitrary SQL commands.
    This issue does not affect you if you only use single-byte (like
    SQL_ASCII or the ISO-8859-X family) or unaffected multibyte (like
    UTF-8) encodings.
    psycopg and python-pgsql use the old encoding for binary data and
    may have to be updated.
The old stable distribution (woody) is affected by these problems but
we\'re unable to correct the package.
For the stable distribution (sarge) these problems have been fixed in
version 7.4.7-6sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 7.4.13-1.
We recommend that you upgrade your postgresql packages.


Solution : http://www.debian.org/security/2006/dsa-1087
Risk factor : High';

if (description) {
 script_id(22629);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1087");
 script_cve_id("CVE-2006-2313", "CVE-2006-2314");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1087] DSA-1087-1 postgresql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1087-1 postgresql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'postgresql', release: '', reference: '7.4.13-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql is vulnerable in Debian .\nUpgrade to postgresql_7.4.13-1\n');
}
if (deb_check(prefix: 'libecpg-dev', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libecpg-dev is vulnerable in Debian 3.1.\nUpgrade to libecpg-dev_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'libecpg4', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libecpg4 is vulnerable in Debian 3.1.\nUpgrade to libecpg4_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'libpgtcl', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpgtcl is vulnerable in Debian 3.1.\nUpgrade to libpgtcl_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'libpgtcl-dev', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpgtcl-dev is vulnerable in Debian 3.1.\nUpgrade to libpgtcl-dev_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'libpq3', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpq3 is vulnerable in Debian 3.1.\nUpgrade to libpq3_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'postgresql', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql is vulnerable in Debian 3.1.\nUpgrade to postgresql_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'postgresql-client', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-client is vulnerable in Debian 3.1.\nUpgrade to postgresql-client_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'postgresql-contrib', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-contrib is vulnerable in Debian 3.1.\nUpgrade to postgresql-contrib_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'postgresql-dev', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-dev is vulnerable in Debian 3.1.\nUpgrade to postgresql-dev_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'postgresql-doc', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql-doc is vulnerable in Debian 3.1.\nUpgrade to postgresql-doc_7.4.7-6sarge2\n');
}
if (deb_check(prefix: 'postgresql', release: '3.1', reference: '7.4.7-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postgresql is vulnerable in Debian sarge.\nUpgrade to postgresql_7.4.7-6sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }

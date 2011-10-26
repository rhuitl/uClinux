# This script was automatically generated from the dsa-935
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE reports that a format string vulnerability in mod_auth_pgsql, a
library used to authenticate web users against a PostgreSQL database,
could be used to execute arbitrary code with the privileges of the httpd
user.
The old stable distribution (woody) does not contain
libapache2-mod-auth-pgsql.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.2b1-5sarge0.
For the unstable distribution (sid) this problem will be fixed shortly.
We recommend that you upgrade your libapache2-mod-auth-pgsql package.


Solution : http://www.debian.org/security/2006/dsa-935
Risk factor : High';

if (description) {
 script_id(22801);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "935");
 script_cve_id("CVE-2005-3656");
 script_bugtraq_id(16153);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA935] DSA-935-1 libapache2-mod-auth-pgsql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-935-1 libapache2-mod-auth-pgsql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache2-mod-auth-pgsql', release: '3.1', reference: '2.0.2b1-5sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache2-mod-auth-pgsql is vulnerable in Debian 3.1.\nUpgrade to libapache2-mod-auth-pgsql_2.0.2b1-5sarge0\n');
}
if (deb_check(prefix: 'libapache2-mod-auth-pgsql', release: '3.1', reference: '2.0.2b1-5sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache2-mod-auth-pgsql is vulnerable in Debian sarge.\nUpgrade to libapache2-mod-auth-pgsql_2.0.2b1-5sarge0\n');
}
if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from the dsa-893
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Remco Verhoef has discovered a vulnerability in acidlab, Analysis
Console for Intrusion Databases, and in acidbase, Basic Analysis and
Security Engine, which can be exploited by malicious users to conduct
SQL injection attacks.
The maintainers of Analysis Console for Intrusion Databases (ACID) in Debian,
of which BASE is a fork off, after a security audit of both BASE and ACID
have determined that the flaw found not only affected the base_qry_main.php (in
BASE) or acid_qry_main.php (in ACID) component but was also found in other
elements of the consoles due to improper parameter validation and filtering.
All the SQL injection bugs and Cross Site Scripting bugs found have been
fixed in the Debian package, closing all the different attack vectors detected.
For the old stable distribution (woody) this problem has been fixed in
version 0.9.6b20-2.1.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.6b20-10.1.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.6b20-13 and in version 1.2.1-1 of acidbase.
We recommend that you upgrade your acidlab and acidbase package.


Solution : http://www.debian.org/security/2005/dsa-893
Risk factor : High';

if (description) {
 script_id(22759);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "893");
 script_cve_id("CVE-2005-3325");
 script_bugtraq_id(15199);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA893] DSA-893-1 acidlab");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-893-1 acidlab");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'acidlab', release: '', reference: '0.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab is vulnerable in Debian .\nUpgrade to acidlab_0.9\n');
}
if (deb_check(prefix: 'acidlab', release: '3.0', reference: '0.9.6b20-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab is vulnerable in Debian 3.0.\nUpgrade to acidlab_0.9.6b20-2.1\n');
}
if (deb_check(prefix: 'acidlab', release: '3.1', reference: '0.9.6b20-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab is vulnerable in Debian 3.1.\nUpgrade to acidlab_0.9.6b20-10.1\n');
}
if (deb_check(prefix: 'acidlab-doc', release: '3.1', reference: '0.9.6b20-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab-doc is vulnerable in Debian 3.1.\nUpgrade to acidlab-doc_0.9.6b20-10.1\n');
}
if (deb_check(prefix: 'acidlab-mysql', release: '3.1', reference: '0.9.6b20-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab-mysql is vulnerable in Debian 3.1.\nUpgrade to acidlab-mysql_0.9.6b20-10.1\n');
}
if (deb_check(prefix: 'acidlab-pgsql', release: '3.1', reference: '0.9.6b20-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab-pgsql is vulnerable in Debian 3.1.\nUpgrade to acidlab-pgsql_0.9.6b20-10.1\n');
}
if (deb_check(prefix: 'acidlab', release: '3.1', reference: '0.9.6b20-10.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab is vulnerable in Debian sarge.\nUpgrade to acidlab_0.9.6b20-10.1\n');
}
if (deb_check(prefix: 'acidlab', release: '3.0', reference: '0.9.6b20-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package acidlab is vulnerable in Debian woody.\nUpgrade to acidlab_0.9.6b20-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

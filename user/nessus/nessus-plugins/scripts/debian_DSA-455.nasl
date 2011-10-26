# This script was automatically generated from the dsa-455
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
libxml2 is a library for manipulating XML files.
Yuuichi Teranishi (&#23546;&#35199; &#35029;&#19968;)
discovered a flaw in libxml, the GNOME XML library.
When fetching a remote resource via FTP or HTTP, the library uses
special parsing routines which can overflow a buffer if passed a very
long URL.  If an attacker is able to find an application using libxml1
or libxml2 that parses remote resources and allows the attacker to
craft the URL, then this flaw could be used to execute arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 1.8.17-2woody1 of libxml and version 2.4.19-4woody1 of libxml2.
For the unstable distribution (sid) this problem has been fixed in
version 1.8.17-5 of libxml and version 2.6.6-1 of libxml2.
We recommend that you upgrade your libxml1 and libxml2 packages.


Solution : http://www.debian.org/security/2004/dsa-455
Risk factor : High';

if (description) {
 script_id(15292);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "455");
 script_cve_id("CVE-2004-0110");
 script_bugtraq_id(9718);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA455] DSA-455-1 libxml");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-455-1 libxml");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libxml-dev', release: '3.0', reference: '1.8.17-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml-dev is vulnerable in Debian 3.0.\nUpgrade to libxml-dev_1.8.17-2woody1\n');
}
if (deb_check(prefix: 'libxml1', release: '3.0', reference: '1.8.17-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml1 is vulnerable in Debian 3.0.\nUpgrade to libxml1_1.8.17-2woody1\n');
}
if (deb_check(prefix: 'libxml2', release: '3.0', reference: '2.4.19-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml2 is vulnerable in Debian 3.0.\nUpgrade to libxml2_2.4.19-4woody1\n');
}
if (deb_check(prefix: 'libxml2-dev', release: '3.0', reference: '2.4.19-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml2-dev is vulnerable in Debian 3.0.\nUpgrade to libxml2-dev_2.4.19-4woody1\n');
}
if (deb_check(prefix: 'libxml,', release: '3.1', reference: '1.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml, is vulnerable in Debian 3.1.\nUpgrade to libxml,_1.8\n');
}
if (deb_check(prefix: 'libxml,', release: '3.0', reference: '1.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml, is vulnerable in Debian woody.\nUpgrade to libxml,_1.8\n');
}
if (w) { security_hole(port: 0, data: desc); }

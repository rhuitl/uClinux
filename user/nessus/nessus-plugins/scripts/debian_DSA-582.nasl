# This script was automatically generated from the dsa-582
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered several buffer overflows in libxml and
libxml2, the XML C parser and toolkits for GNOME.  Missing boundary
checks could cause several buffers to be overflown, which may cause
the client to execute arbitrary code.
The following vulnerability matrix lists corrected versions of these
libraries:
For the stable distribution (woody) these problems have been fixed in
version 1.8.17-2woody2 of libxml and in version 2.4.19-4woody2 of
libxml2.
For the unstable distribution (sid) these problems have been fixed in
version 1.8.17-9 of libxml and in version 2.6.11-5 of libxml2.
These problems have also been fixed in version 2.6.15-1 of libxml2 in
the experimental distribution.
We recommend that you upgrade your libxml packages.


Solution : http://www.debian.org/security/2004/dsa-582
Risk factor : High';

if (description) {
 script_id(15680);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "582");
 script_cve_id("CVE-2004-0989");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA582] DSA-582-1 libxml");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-582-1 libxml");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libxml-dev', release: '3.0', reference: '1.8.17-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml-dev is vulnerable in Debian 3.0.\nUpgrade to libxml-dev_1.8.17-2woody2\n');
}
if (deb_check(prefix: 'libxml1', release: '3.0', reference: '1.8.17-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml1 is vulnerable in Debian 3.0.\nUpgrade to libxml1_1.8.17-2woody2\n');
}
if (deb_check(prefix: 'libxml2', release: '3.0', reference: '2.4.19-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml2 is vulnerable in Debian 3.0.\nUpgrade to libxml2_2.4.19-4woody2\n');
}
if (deb_check(prefix: 'libxml2-dev', release: '3.0', reference: '2.4.19-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxml2-dev is vulnerable in Debian 3.0.\nUpgrade to libxml2-dev_2.4.19-4woody2\n');
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

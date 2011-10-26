# This script was automatically generated from the dsa-426
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
netpbm is a graphics conversion toolkit made up of a large number of
single-purpose programs.  Many of these programs were found to create
temporary files in an insecure manner, which could allow a local
attacker to overwrite files with the privileges of the user invoking a
vulnerable netpbm tool.
For the current stable distribution (woody) these problems have been
fixed in version 2:9.20-8.4.
For the unstable distribution (sid) these problems have been fixed in
version 2:9.25-9.
We recommend that you update your netpbm-free package.


Solution : http://www.debian.org/security/2004/dsa-426
Risk factor : High';

if (description) {
 script_id(15263);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "426");
 script_cve_id("CVE-2003-0924");
 script_bugtraq_id(9442);
 script_xref(name: "CERT", value: "487102");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA426] DSA-426-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-426-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libnetpbm9', release: '3.0', reference: '9.20-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9 is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9_9.20-8.4\n');
}
if (deb_check(prefix: 'libnetpbm9-dev', release: '3.0', reference: '9.20-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9-dev is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9-dev_9.20-8.4\n');
}
if (deb_check(prefix: 'netpbm', release: '3.0', reference: '9.20-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm is vulnerable in Debian 3.0.\nUpgrade to netpbm_9.20-8.4\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.1', reference: '9.25-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian 3.1.\nUpgrade to netpbm-free_9.25-9\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.0', reference: '9.20-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian woody.\nUpgrade to netpbm-free_9.20-8.4\n');
}
if (w) { security_hole(port: 0, data: desc); }

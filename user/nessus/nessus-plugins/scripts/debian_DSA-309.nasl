# This script was automatically generated from the dsa-309
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"bazarr" discovered that eterm is vulnerable to a buffer overflow of
the ETERMPATH environment variable.  This bug can be exploited to gain
the privileges of the group "utmp" on a system where eterm is
installed.
For the stable distribution (woody), this problem has been fixed in
version 0.9.2-0pre2002042903.1.
The old stable distribution (potato) is not affected by this bug.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your eterm package.


Solution : http://www.debian.org/security/2003/dsa-309
Risk factor : High';

if (description) {
 script_id(15146);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "309");
 script_cve_id("CVE-2003-0382");
 script_bugtraq_id(7708);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA309] DSA-309-1 eterm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-309-1 eterm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'eterm', release: '3.0', reference: '0.9.2-0pre2002042903.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eterm is vulnerable in Debian 3.0.\nUpgrade to eterm_0.9.2-0pre2002042903.1\n');
}
if (deb_check(prefix: 'eterm', release: '3.0', reference: '0.9.2-0pre2002042903.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package eterm is vulnerable in Debian woody.\nUpgrade to eterm_0.9.2-0pre2002042903.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

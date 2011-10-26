# This script was automatically generated from the dsa-836
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña discovered insecure temporary file use
in cfengine2, a tool for configuring and maintaining networked
machines, that can be exploited by a symlink attack to overwrite
arbitrary files owned by the user executing cfengine, which is
probably root.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.14-1sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your cfengine2 package.


Solution : http://www.debian.org/security/2005/dsa-836
Risk factor : High';

if (description) {
 script_id(19805);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "836");
 script_cve_id("CVE-2005-2960", "CVE-2005-3137");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA836] DSA-836-1 cfengine2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-836-1 cfengine2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cfengine2', release: '3.1', reference: '2.1.14-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine2 is vulnerable in Debian 3.1.\nUpgrade to cfengine2_2.1.14-1sarge1\n');
}
if (deb_check(prefix: 'cfengine2-doc', release: '3.1', reference: '2.1.14-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine2-doc is vulnerable in Debian 3.1.\nUpgrade to cfengine2-doc_2.1.14-1sarge1\n');
}
if (deb_check(prefix: 'cfengine2', release: '3.1', reference: '2.1.14-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfengine2 is vulnerable in Debian sarge.\nUpgrade to cfengine2_2.1.14-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }

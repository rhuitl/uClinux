# This script was automatically generated from the dsa-857
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña discovered insecure temporary file
creation in graphviz, a rich set of graph drawing tools, that can be
exploited to overwrite arbitrary files by a local attacker.
For the old stable distribution (woody) this problem probably persists
but the package is non-free.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.1-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.1-1sarge1.
We recommend that you upgrade your graphviz package.


Solution : http://www.debian.org/security/2005/dsa-857
Risk factor : High';

if (description) {
 script_id(19965);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "857");
 script_cve_id("CVE-2005-2965");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA857] DSA-857-1 graphviz");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-857-1 graphviz");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'graphviz', release: '', reference: '2.2.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package graphviz is vulnerable in Debian .\nUpgrade to graphviz_2.2.1-1sarge1\n');
}
if (deb_check(prefix: 'graphviz', release: '3.1', reference: '2.2.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package graphviz is vulnerable in Debian 3.1.\nUpgrade to graphviz_2.2.1-1sarge1\n');
}
if (deb_check(prefix: 'graphviz-dev', release: '3.1', reference: '2.2.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package graphviz-dev is vulnerable in Debian 3.1.\nUpgrade to graphviz-dev_2.2.1-1sarge1\n');
}
if (deb_check(prefix: 'graphviz-doc', release: '3.1', reference: '2.2.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package graphviz-doc is vulnerable in Debian 3.1.\nUpgrade to graphviz-doc_2.2.1-1sarge1\n');
}
if (deb_check(prefix: 'graphviz', release: '3.1', reference: '2.2.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package graphviz is vulnerable in Debian sarge.\nUpgrade to graphviz_2.2.1-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }

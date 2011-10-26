# This script was automatically generated from the dsa-196
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
[Bind version 9, the bind9 package, is not affected by these problems.]
ISS X-Force has discovered several serious vulnerabilities in the Berkeley
Internet Name Domain Server (BIND).  BIND is the most common implementation
of the DNS (Domain Name Service) protocol, which is used on the vast
majority of DNS servers on the Internet.  DNS is a vital Internet protocol
that maintains a database of easy-to-remember domain names (host names) and
their corresponding numerical IP addresses.
Circumstantial evidence suggests that the Internet Software Consortium
(ISC), maintainers of BIND, was made aware of these issues in mid-October.
Distributors of Open Source operating systems, including Debian, were
notified of these vulnerabilities via CERT about 12 hours before the release
of the advisories on November 12th.  This notification did not include any
details that allowed us to identify the vulnerable code, much less prepare
timely fixes.
Unfortunately ISS and the ISC released their security advisories with only
descriptions of the vulnerabilities, without any patches.  Even though there
were no signs that these exploits are known to the black-hat community, and
there were no reports of active attacks, such attacks could have been
developed in the meantime - with no fixes available.
We can all express our regret at the inability of the ironically named
Internet Software Consortium to work with the Internet community in handling
this problem.  Hopefully this will not become a model for dealing with
security issues in the future.
The Common Vulnerabilities and Exposures (CVE) project identified the
following vulnerabilities:
These problems have been fixed in version 8.3.3-2.0woody1 for the current
stable distribution (woody), in version 8.2.3-0.potato.3 for the previous stable
distribution (potato) and in version 8.3.3-3 for the unstable distribution
(sid).  The fixed packages for unstable will enter the archive today.
We recommend that you upgrade your bind package immediately, update to
bind9, or switch to another DNS server implementation.


Solution : http://www.debian.org/security/2002/dsa-196
Risk factor : High';

if (description) {
 script_id(15033);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-a-0006");
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "196");
 script_cve_id("CVE-2002-0029", "CVE-2002-1219", "CVE-2002-1220", "CVE-2002-1221");
 script_bugtraq_id(6159, 6160, 6161);
 script_xref(name: "CERT", value: "229595");
 script_xref(name: "CERT", value: "542971");
 script_xref(name: "CERT", value: "581682");
 script_xref(name: "CERT", value: "844360");
 script_xref(name: "CERT", value: "852283");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA196] DSA-196-1 bind");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-196-1 bind");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bind', release: '2.2', reference: '8.2.3-0.potato.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind is vulnerable in Debian 2.2.\nUpgrade to bind_8.2.3-0.potato.3\n');
}
if (deb_check(prefix: 'bind-dev', release: '2.2', reference: '8.2.3-0.potato.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind-dev is vulnerable in Debian 2.2.\nUpgrade to bind-dev_8.2.3-0.potato.3\n');
}
if (deb_check(prefix: 'bind-doc', release: '2.2', reference: '8.2.3-0.potato.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind-doc is vulnerable in Debian 2.2.\nUpgrade to bind-doc_8.2.3-0.potato.3\n');
}
if (deb_check(prefix: 'dnsutils', release: '2.2', reference: '8.2.3-0.potato.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dnsutils is vulnerable in Debian 2.2.\nUpgrade to dnsutils_8.2.3-0.potato.3\n');
}
if (deb_check(prefix: 'task-dns-server', release: '2.2', reference: '8.2.3-0.potato.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package task-dns-server is vulnerable in Debian 2.2.\nUpgrade to task-dns-server_8.2.3-0.potato.3\n');
}
if (deb_check(prefix: 'bind', release: '3.0', reference: '8.3.3-2.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind is vulnerable in Debian 3.0.\nUpgrade to bind_8.3.3-2.0woody1\n');
}
if (deb_check(prefix: 'bind-dev', release: '3.0', reference: '8.3.3-2.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind-dev is vulnerable in Debian 3.0.\nUpgrade to bind-dev_8.3.3-2.0woody1\n');
}
if (deb_check(prefix: 'bind-doc', release: '3.0', reference: '8.3.3-2.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind-doc is vulnerable in Debian 3.0.\nUpgrade to bind-doc_8.3.3-2.0woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }

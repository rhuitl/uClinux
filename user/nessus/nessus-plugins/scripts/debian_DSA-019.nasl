# This script was automatically generated from the dsa-019
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'WireX discovered a potential temporary file race condition
in the way that squid sends out email messages notifying the administrator
about updating the program. This could lead to arbitrary files to get
overwritten. However the code would only be executed if running a very bleeding
edge release of squid, running a server whose time is set some number of months
in the past and squid is crashing. Read it as hardly to exploit. This version
also contains more upstream bugfixes wrt. dots in hostnames and improper HTML
quoting.


Solution : http://www.debian.org/security/2001/dsa-019
Risk factor : High';

if (description) {
 script_id(14856);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "019");
 script_cve_id("CVE-2001-0142");
 script_bugtraq_id(2184);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA019] DSA-019-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-019-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '2.2', reference: '2.2.5-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 2.2.\nUpgrade to squid_2.2.5-3.1\n');
}
if (deb_check(prefix: 'squid-cgi', release: '2.2', reference: '2.2.5-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 2.2.\nUpgrade to squid-cgi_2.2.5-3.1\n');
}
if (deb_check(prefix: 'squidclient', release: '2.2', reference: '2.2.5-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 2.2.\nUpgrade to squidclient_2.2.5-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from the dsa-389
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
ipmasq is a package which simplifies configuration of Linux IP
masquerading, a form of network address translation which allows a
number of hosts to share a single public IP address.  Due to use of
certain improper filtering rules, traffic arriving on the external
interface addressed for an internal host would be forwarded,
regardless of whether it was associated with an established
connection.  This vulnerability could be exploited by an attacker
capable of forwarding IP traffic with an arbitrary destination address
to the external interface of a system with ipmasq installed.
For the current stable distribution (woody) this problem has been
fixed in version 3.5.10c.
For the unstable distribution (sid) this problem has been fixed in
version 3.5.12.
We recommend that you update your ipmasq package.


Solution : http://www.debian.org/security/2003/dsa-389
Risk factor : High';

if (description) {
 script_id(15226);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "389");
 script_cve_id("CVE-2003-0785");
 script_bugtraq_id(8664);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA389] DSA-389-1 ipmasq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-389-1 ipmasq");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ipmasq', release: '3.0', reference: '3.5.10c')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipmasq is vulnerable in Debian 3.0.\nUpgrade to ipmasq_3.5.10c\n');
}
if (deb_check(prefix: 'ipmasq', release: '3.1', reference: '3.5.12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipmasq is vulnerable in Debian 3.1.\nUpgrade to ipmasq_3.5.12\n');
}
if (deb_check(prefix: 'ipmasq', release: '3.0', reference: '3.5.10c')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipmasq is vulnerable in Debian woody.\nUpgrade to ipmasq_3.5.10c\n');
}
if (w) { security_hole(port: 0, data: desc); }

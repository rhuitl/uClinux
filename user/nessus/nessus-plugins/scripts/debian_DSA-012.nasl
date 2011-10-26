# This script was automatically generated from the dsa-012
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'PkC has reported that there is a buffer overflow in
sprintf() in micq versions 0.4.6 and previous, that allows to a remote attacker
able to sniff packets to the ICQ server to execute arbitrary code on the victim
system.

We recommend you upgrade your micq package immediately.


Solution : http://www.debian.org/security/2001/dsa-012
Risk factor : High';

if (description) {
 script_id(14849);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "012");
 script_cve_id("CVE-2001-0233");
 script_bugtraq_id(2254);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA012] DSA-012-1 micq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-012-1 micq");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'micq', release: '2.2', reference: '0.4.3-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package micq is vulnerable in Debian 2.2.\nUpgrade to micq_0.4.3-4\n');
}
if (w) { security_hole(port: 0, data: desc); }

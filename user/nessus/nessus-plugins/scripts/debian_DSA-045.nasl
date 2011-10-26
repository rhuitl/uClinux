# This script was automatically generated from the dsa-045
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Przemyslaw Frasunek <venglin@FREEBSD.LUBLIN.PL>
reported that ntp daemons such as that released with Debian GNU/Linux are
vulnerable to a buffer overflow that can lead to a remote root exploit. A
previous advisory (DSA-045-1) partially addressed this issue, but introduced a
potential denial of service attack. This has been corrected for Debian 2.2
(potato) in ntp version 4.0.99g-2potato2.


Solution : http://www.debian.org/security/2001/dsa-045
Risk factor : High';

if (description) {
 script_id(14882);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "045");
 script_cve_id("CVE-2001-0414");
 script_bugtraq_id(2450);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA045] DSA-045-2 ntpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-045-2 ntpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ntp', release: '2.2', reference: '4.0.99g-2potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp is vulnerable in Debian 2.2.\nUpgrade to ntp_4.0.99g-2potato2\n');
}
if (deb_check(prefix: 'ntp-doc', release: '2.2', reference: '4.0.99g-2potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntp-doc is vulnerable in Debian 2.2.\nUpgrade to ntp-doc_4.0.99g-2potato2\n');
}
if (deb_check(prefix: 'ntpdate', release: '2.2', reference: '4.0.99g-2potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ntpdate is vulnerable in Debian 2.2.\nUpgrade to ntpdate_4.0.99g-2potato2\n');
}
if (deb_check(prefix: 'xntp3', release: '2.2', reference: '4.0.99g-2potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xntp3 is vulnerable in Debian 2.2.\nUpgrade to xntp3_4.0.99g-2potato2\n');
}
if (w) { security_hole(port: 0, data: desc); }

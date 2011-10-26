# This script was automatically generated from the dsa-186
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Enrico Zini discovered a buffer overflow in log2mail, a daemon for
watching logfiles and sending lines with matching patterns via mail.
The log2mail daemon is started upon system boot and runs as root.  A
specially crafted (remote) log message could overflow a static buffer,
potentially leaving log2mail to execute arbitrary code as root.
This problem has been fixed in version 0.2.5.1 the current
stable distribution (woody) and in version 0.2.6-1 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn\'t contain a log2mail package.
We recommend that you upgrade your log2mail package.


Solution : http://www.debian.org/security/2002/dsa-186
Risk factor : High';

if (description) {
 script_id(15023);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "186");
 script_cve_id("CVE-2002-1251");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA186] DSA-186-1 log2mail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-186-1 log2mail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'log2mail', release: '3.0', reference: '0.2.5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package log2mail is vulnerable in Debian 3.0.\nUpgrade to log2mail_0.2.5.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

# This script was automatically generated from the dsa-026
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'BIND 8 suffered from several buffer overflows. It is
possible to construct an inverse query that allows the stack to be read
remotely exposing environment variables. CERT has disclosed information about
these issues. A new upstream version fixes this. Due to the complexity of BIND
we have decided to make an exception to our rule by releasing the new upstream
source to our stable distribution. We recommend you upgrade your bind packages
immediately.


Solution : http://www.debian.org/security/2001/dsa-026
Risk factor : High';

if (description) {
 script_id(14863);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "026");
 script_cve_id("CVE-2001-0010", "CVE-2001-0012");
 script_xref(name: "CERT", value: "196945");
 script_xref(name: "CERT", value: "325431");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA026] DSA-026-1 bind");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-026-1 bind");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bind', release: '2.2', reference: '8.2.3-0.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind is vulnerable in Debian 2.2.\nUpgrade to bind_8.2.3-0.potato.1\n');
}
if (deb_check(prefix: 'bind-dev', release: '2.2', reference: '8.2.3-0.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind-dev is vulnerable in Debian 2.2.\nUpgrade to bind-dev_8.2.3-0.potato.1\n');
}
if (deb_check(prefix: 'dnsutils', release: '2.2', reference: '8.2.3-0.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dnsutils is vulnerable in Debian 2.2.\nUpgrade to dnsutils_8.2.3-0.potato.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

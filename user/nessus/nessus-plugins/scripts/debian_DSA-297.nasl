# This script was automatically generated from the dsa-297
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in Snort, a popular network
intrusion detection system.  Snort comes with modules and plugins that
perform a variety of functions such as protocol analysis.  The
following issues have been identified:
For the stable distribution (woody) these problems have been fixed in
version 1.8.4beta1-3.1.
The old stable distribution (potato) is not affected by these problems
since it doesn\'t contain the problematic code.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.0-1.
We recommend that you upgrade your snort package immediately.
You are also advised to upgrade to the most recent version of Snort,
since Snort, as any intrusion detection system, is rather useless if
it is based on old and out-dated data and not kept up to date.  Such
installations would be unable to detect intrusions using modern
methods.  The current version of Snort is 2.0.0, while the version in
the stable distribution (1.8) is quite old and the one in the old
stable distribution is beyond hope.
Since Debian does not update arbitrary packages in stable releases,
even Snort is not going to see updates other than to fix security
problems, you are advised to upgrade to the most recent version from
third party sources.
The Debian maintainer for Snort provides backported up-to-date
packages for woody (stable) and potato (oldstable) for cases where you
cannot upgrade your entire system.  These packages are untested,
though and only exist for the i386 architecture:

deb     http://people.debian.org/~ssmeenk/snort-stable-i386/ ./
deb-src http://people.debian.org/~ssmeenk/snort-stable-i386/ ./

deb     http://people.debian.org/~ssmeenk/snort-oldstable-i386/ ./
deb-src http://people.debian.org/~ssmeenk/snort-oldstable-i386/ ./




Solution : http://www.debian.org/security/2003/dsa-297
Risk factor : High';

if (description) {
 script_id(15134);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-a-0008");
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "297");
 script_cve_id("CVE-2003-0033", "CVE-2003-0209");
 script_bugtraq_id(6963, 7178);
 script_xref(name: "CERT", value: "139129");
 script_xref(name: "CERT", value: "916785");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA297] DSA-297-1 snort");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-297-1 snort");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'snort', release: '3.0', reference: '1.8.4beta1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snort is vulnerable in Debian 3.0.\nUpgrade to snort_1.8.4beta1-3.1\n');
}
if (deb_check(prefix: 'snort-common', release: '3.0', reference: '1.8.4beta1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snort-common is vulnerable in Debian 3.0.\nUpgrade to snort-common_1.8.4beta1-3.1\n');
}
if (deb_check(prefix: 'snort-doc', release: '3.0', reference: '1.8.4beta1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snort-doc is vulnerable in Debian 3.0.\nUpgrade to snort-doc_1.8.4beta1-3.1\n');
}
if (deb_check(prefix: 'snort-mysql', release: '3.0', reference: '1.8.4beta1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snort-mysql is vulnerable in Debian 3.0.\nUpgrade to snort-mysql_1.8.4beta1-3.1\n');
}
if (deb_check(prefix: 'snort-rules-default', release: '3.0', reference: '1.8.4beta1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snort-rules-default is vulnerable in Debian 3.0.\nUpgrade to snort-rules-default_1.8.4beta1-3.1\n');
}
if (deb_check(prefix: 'snort', release: '3.1', reference: '2.0.0-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snort is vulnerable in Debian 3.1.\nUpgrade to snort_2.0.0-1\n');
}
if (deb_check(prefix: 'snort', release: '3.0', reference: '1.8.4beta1-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snort is vulnerable in Debian woody.\nUpgrade to snort_1.8.4beta1-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

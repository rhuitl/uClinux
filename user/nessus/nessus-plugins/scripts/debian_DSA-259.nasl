# This script was automatically generated from the dsa-259
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Florian Heinz heinz@cronon-ag.de posted to the Bugtraq mailing list an
exploit for qpopper based on a bug in the included vsnprintf implementation.
The sample exploit requires a valid user account and password, and overflows a
string in the pop_msg() function to give the user "mail" group privileges and a
shell on the system. Since the Qvsnprintf function is used elsewhere in
qpopper, additional exploits may be possible.
The qpopper package in Debian 2.2 (potato) does not include the vulnerable
snprintf implementation. For Debian 3.0 (woody) an updated package is available
in version 4.0.4-2.woody.3. Users running an unreleased version of Debian
should upgrade to 4.0.4-9 or newer. We recommend you upgrade your qpopper
package immediately.


Solution : http://www.debian.org/security/2003/dsa-259
Risk factor : High';

if (description) {
 script_id(15096);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "259");
 script_cve_id("CVE-2003-0143");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA259] DSA-259-1 qpopper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-259-1 qpopper");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'qpopper', release: '3.0', reference: '4.0.4-2.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper is vulnerable in Debian 3.0.\nUpgrade to qpopper_4.0.4-2.woody.3\n');
}
if (deb_check(prefix: 'qpopper-drac', release: '3.0', reference: '4.0.4-2.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper-drac is vulnerable in Debian 3.0.\nUpgrade to qpopper-drac_4.0.4-2.woody.3\n');
}
if (w) { security_hole(port: 0, data: desc); }

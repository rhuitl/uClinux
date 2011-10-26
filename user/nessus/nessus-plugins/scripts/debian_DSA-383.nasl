# This script was automatically generated from the dsa-383
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several bugs have been found in OpenSSH\'s buffer handling. It is not
known if these bugs are exploitable, but as a precaution an upgrade is
advised.
DSA-383-2:
This advisory is an addition to the earlier DSA-383-1 advisory: Solar
Designer found four more bugs in OpenSSH that may be exploitable.
For the Debian stable distribution these bugs have been fixed in version
1:3.4p1-0woody4.
We recommend that you update your ssh-krb5 package.


Solution : http://www.debian.org/security/2003/dsa-383
Risk factor : High';

if (description) {
 script_id(15220);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "383");
 script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695");
 script_bugtraq_id(8628);
 script_xref(name: "CERT", value: "333628");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA383] DSA-383-2 ssh-krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-383-2 ssh-krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ssh-krb5', release: '3.0', reference: '3.4p1-0woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssh-krb5 is vulnerable in Debian 3.0.\nUpgrade to ssh-krb5_3.4p1-0woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }

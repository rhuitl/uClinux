# This script was automatically generated from the dsa-125
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Yuji Takahashi discovered a bug in analog which allows a cross-site
scripting type attack.  It is easy for an attacker to insert arbitrary
strings into any web server logfile.  If these strings are then
analysed by analog, they can appear in the report.  By this means an
attacker can introduce arbitrary Javascript code, for example, into an
analog report produced by someone else and read by a third person.
Analog already attempted to encode unsafe characters to avoid this
type of attack, but the conversion was incomplete.
This problem has been fixed in the upstream version 5.22 of analog.
Unfortunately patching the old version of analog in the stable
distribution of Debian instead is a very large job that defeats us.
We recommend that you upgrade your analog package immediately.


Solution : http://www.debian.org/security/2002/dsa-125
Risk factor : High';

if (description) {
 script_id(14962);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "125");
 script_cve_id("CVE-2002-0166");
 script_bugtraq_id(4389);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA125] DSA-125-1 analog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-125-1 analog");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'analog', release: '2.2', reference: '5.22-0potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package analog is vulnerable in Debian 2.2.\nUpgrade to analog_5.22-0potato1\n');
}
if (w) { security_hole(port: 0, data: desc); }

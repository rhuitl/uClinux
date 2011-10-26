# This script was automatically generated from the dsa-156
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
All versions of the EPIC script Light prior to 2.7.30p5 (on the 2.7
branch) and prior to 2.8pre10 (on the 2.8 branch) running on any
platform are vulnerable to a remotely-exploitable bug, which can lead
to nearly arbitrary code execution.
This problem has been fixed in version 2.7.30p5-1.1 for the current
stable distribution (woody) and in version 2.7.30p5-2 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected, since it doesn\'t contain the Light package.
We recommend that you upgrade your epic4-script-light package and
restart your IRC client.


Solution : http://www.debian.org/security/2002/dsa-156
Risk factor : High';

if (description) {
 script_id(14993);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "156");
 script_cve_id("CVE-2002-0984");
 script_bugtraq_id(5555);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA156] DSA-156-1 epic4-script-light");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-156-1 epic4-script-light");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'epic4-script-light', release: '3.0', reference: '2.7.30p5-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package epic4-script-light is vulnerable in Debian 3.0.\nUpgrade to epic4-script-light_2.7.30p5-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }

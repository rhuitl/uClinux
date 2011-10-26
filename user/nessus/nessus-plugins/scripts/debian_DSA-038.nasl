# This script was automatically generated from the dsa-038
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'Former versions of sgml-tools created temporary files
directly in /tmp in an insecure fashion.  Version 1.0.9-15 and higher create a
subdirectory first and open temporary files within that directory. This has
been fixed in sgml-tools 1.0.9-15


Solution : http://www.debian.org/security/2001/dsa-038
Risk factor : High';

if (description) {
 script_id(14875);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "038");
 script_cve_id("CVE-2001-0416");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA038] DSA-038-1 sgml-tools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-038-1 sgml-tools");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sgml-tools', release: '2.2', reference: '1.0.9-15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sgml-tools is vulnerable in Debian 2.2.\nUpgrade to sgml-tools_1.0.9-15\n');
}
if (w) { security_hole(port: 0, data: desc); }

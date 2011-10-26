# This script was automatically generated from the dsa-130
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ethereal versions prior to 0.9.3 were vulnerable to an allocation error
in the ASN.1 parser. This can be triggered when analyzing traffic using
the SNMP, LDAP, COPS, or Kerberos protocols in ethereal. This
vulnerability was announced in the ethereal security advisory
enpa-sa-00003.
This issue has been corrected in ethereal version 0.8.0-3potato for
Debian 2.2 (potato).
Additionally, a number of vulnerabilities were discussed in ethereal
security advisory
enpa-sa-00004;
the version of ethereal in Debian 2.2
(potato) is not vulnerable to the issues raised in this later advisory.
Users of the not-yet-released woody distribution should ensure that they
are running ethereal 0.9.4-1 or a later version.
We recommend you upgrade your ethereal package immediately.


Solution : http://www.debian.org/security/2002/dsa-130
Risk factor : High';

if (description) {
 script_id(14967);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "130");
 script_cve_id("CVE-2002-0353", "CVE-2002-0401", "CVE-2002-0402", "CVE-2002-0403", "CVE-2002-0404");
 script_bugtraq_id(4604, 4805, 4806, 4807, 4808);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA130] DSA-130-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-130-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '2.2', reference: '0.8.0-3potato')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 2.2.\nUpgrade to ethereal_0.8.0-3potato\n');
}
if (w) { security_hole(port: 0, data: desc); }

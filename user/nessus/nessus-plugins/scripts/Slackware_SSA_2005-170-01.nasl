# This script was automatically generated from the SSA-2005-170-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Sun has released a couple of security advisories pertaining to both the
Java Runtime Environment and the Standard Edition Development Kit.
These could allow applets to read or write to local files.  For more
details, Sun\'s advisories may be found here:

  http://sunsolve.sun.com/search/document.do?assetkey=1-26-101748-1
  http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1

Slackware repackage\'s Sun\'s Java(TM) binaries without changing them, so
the packages from Slackware -current should be used for all glibc based
Slackware versions.


Here are the details from the Slackware -current ChangeLog:
+--------------------------+
Sun Jun 19 21:45:07 PDT 2005
l/jre-1_5_0_03-i586-1.tgz:  This already-issued package fixes some
  recently announced security issues that could allow applets to read
  or write to local files.  See:
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-101748-1
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1
  (* Security fix *)
extra/j2sdk-1.5.0_03/j2sdk-1_5_0_03-i586-1.tgz:  Fixed the slack-desc
  to not include the release version to prevent future mishaps. :-)
  This already-issued package fixes some recently announced security
  issues that could allow applets to read or write to local files.
  See:
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-101748-1
    http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1
  (* Security fix *)
+--------------------------+

';
if (description) {
script_id(18802);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-170-01");
script_summary("SSA-2005-170-01 java (jre, j2sdk) ");
name["english"] = "SSA-2005-170-01 java (jre, j2sdk) ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "", pkgname: "jre", pkgver: "1_5_0_03", pkgnum:  "1", pkgarch: "i586")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package jre is vulnerable in Slackware 
Upgrade to jre-1_5_0_03-i586-1 or newer.
');
}
if (slackware_check(osver: "", pkgname: "j2sdk", pkgver: "1_5_0_03", pkgnum:  "1", pkgarch: "i586")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package j2sdk is vulnerable in Slackware 
Upgrade to j2sdk-1_5_0_03-i586-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }

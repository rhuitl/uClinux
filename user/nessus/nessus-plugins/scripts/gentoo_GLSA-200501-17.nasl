# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16408);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-17");
 script_cve_id("CVE-2004-1125");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-17
(KPdf, KOffice: More vulnerabilities in included Xpdf)


    KPdf and KOffice both include Xpdf code to handle PDF files. Xpdf is
    vulnerable to multiple new integer overflows, as described in GLSA
    200412-24.
  
Impact

    An attacker could entice a user to open a specially-crafted PDF file,
    potentially resulting in the execution of arbitrary code with the
    rights of the user running the affected utility.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200412-24.xml
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1125
    http://kde.org/info/security/advisory-20041223-1.txt
    http://koffice.kde.org/security/2004_xpdf_integer_overflow_2.php


Solution: 
    All KPdf users should upgrade to the latest version of kdegraphics:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdegraphics
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-office/koffice
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-17] KPdf, KOffice: More vulnerabilities in included Xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KPdf, KOffice: More vulnerabilities in included Xpdf');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.3.2-r1", "rge 3.2.3-r3"), vulnerable: make_list("lt 3.3.2-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/koffice", unaffected: make_list("ge 1.3.5-r1"), vulnerable: make_list("lt 1.3.5-r1")
)) { security_warning(0); exit(0); }

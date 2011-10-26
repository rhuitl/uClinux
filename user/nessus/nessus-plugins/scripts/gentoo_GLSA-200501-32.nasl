# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-32.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16423);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-32");
 script_cve_id("CVE-2005-0064");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-32
(KPdf, KOffice: Stack overflow in included Xpdf code)


    KPdf and KOffice both include Xpdf code to handle PDF files. Xpdf
    is vulnerable to a new stack overflow, as described in GLSA 200501-28.
  
Impact

    An attacker could entice a user to open a specially-crafted PDF
    file, potentially resulting in the execution of arbitrary code with the
    rights of the user running the affected application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200501-28.xml
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0064
    http://www.kde.org/info/security/advisory-20050119-1.txt
    http://www.kde.org/info/security/advisory-20050120-1.txt


Solution: 
    All KPdf users should upgrade to the latest version of
    kdegraphics:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdegraphics
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-office/koffice
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-32] KPdf, KOffice: Stack overflow in included Xpdf code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KPdf, KOffice: Stack overflow in included Xpdf code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.3.2-r2", "rge 3.2.3-r4"), vulnerable: make_list("lt 3.3.2-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/koffice", unaffected: make_list("ge 1.3.5-r2"), vulnerable: make_list("lt 1.3.5-r2")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20895);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-05");
 script_cve_id("CVE-2006-0301");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-05
(KPdf: Heap based overflow)


    KPdf includes Xpdf code to handle PDF files. Dirk Mueller
    discovered that the Xpdf code is vulnerable a heap based overflow in
    the splash rasterizer engine.
  
Impact

    An attacker could entice a user to open a specially crafted PDF
    file with Kpdf, potentially resulting in the execution of arbitrary
    code with the rights of the user running the affected application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0301
    http://www.kde.org/info/security/advisory-20060202-1.txt


Solution: 
    All kdegraphics users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdegraphics-3.4.3-r4"
    All Kpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kpdf-3.4.3-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-05] KPdf: Heap based overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KPdf: Heap based overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.4.3-r4"), vulnerable: make_list("lt 3.4.3-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kpdf", unaffected: make_list("ge 3.4.3-r4"), vulnerable: make_list("lt 3.4.3-r4")
)) { security_warning(0); exit(0); }

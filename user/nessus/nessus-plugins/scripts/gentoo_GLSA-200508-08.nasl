# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19441);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-08
(Xpdf, Kpdf, GPdf: Denial of Service vulnerability)


    Xpdf, Kpdf and GPdf do not handle a broken table of embedded
    TrueType fonts correctly. After detecting such a table, Xpdf, Kpdf and
    GPdf attempt to reconstruct the information in it by decoding the PDF
    file, which causes the generation of a huge temporary file.
  
Impact

    A remote attacker may cause a Denial of Service by creating a
    specially crafted PDF file, sending it to a CUPS printing system (which
    uses Xpdf), or by enticing a user to open it in Xpdf, Kpdf, or GPdf.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2097


Solution: 
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.00-r10"
    All GPdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-2.10.0-r1"
    All Kpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdegraphics-3.3.2-r3"
    All KDE Split Ebuild Kpdf users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kpdf-3.4.1-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-08] Xpdf, Kpdf, GPdf: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, Kpdf, GPdf: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.10.0-r1"), vulnerable: make_list("lt 2.10.0-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kpdf", unaffected: make_list("ge 3.4.1-r1"), vulnerable: make_list("lt 3.4.1-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.00-r10"), vulnerable: make_list("lt 3.00-r10")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.3.2-r3"), vulnerable: make_list("lt 3.3.2-r3")
)) { security_warning(0); exit(0); }

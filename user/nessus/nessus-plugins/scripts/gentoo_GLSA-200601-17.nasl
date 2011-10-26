# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20829);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-17");
 script_cve_id("CVE-2005-3627", "CVE-2005-3626", "CVE-2005-3625", "CVE-2005-3624");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-17
(Xpdf, Poppler, GPdf, libextractor, pdftohtml: Heap overflows)


    Chris Evans has reported some integer overflows in Xpdf when
    attempting to calculate buffer sizes for memory allocation, leading to
    a heap overflow and a potential infinite loop when handling malformed
    input files.
  
Impact

    By sending a specially crafted PDF file to a victim, an attacker
    could cause an overflow, potentially resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3627
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3626
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3625
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3624


Solution: 
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.01-r5"
    All Poppler users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/poppler-0.4.3-r4"
    All GPdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-2.10.0-r3"
    All libextractor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/libextractor-0.5.9"
    All pdftohtml users should migrate to the latest stable version
    of Poppler.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-17] Xpdf, Poppler, GPdf, libextractor, pdftohtml: Heap overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, Poppler, GPdf, libextractor, pdftohtml: Heap overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/pdftohtml", unaffected: make_list(), vulnerable: make_list("lt 0.36-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.01-r5"), vulnerable: make_list("lt 3.01-r5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/poppler", unaffected: make_list("ge 0.4.3-r4"), vulnerable: make_list("lt 0.4.3-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.10.0-r3"), vulnerable: make_list("lt 2.10.0-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-libs/libextractor", unaffected: make_list("ge 0.5.9"), vulnerable: make_list("lt 0.5.9")
)) { security_warning(0); exit(0); }

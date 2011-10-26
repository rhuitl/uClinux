# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-30.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15582);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200410-30");
 script_cve_id("CVE-2004-0888", "CVE-2004-0889");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-30
(GPdf, KPDF, KOffice: Vulnerabilities in included xpdf)


    GPdf, KPDF and KOffice all include xpdf code to handle PDF files. xpdf is
    vulnerable to multiple integer overflows, as described in GLSA 200410-20.
  
Impact

    An attacker could entice a user to open a specially-crafted PDF file,
    potentially resulting in execution of arbitrary code with the rights of the
    user running the affected utility.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gentoo.org/security/en/glsa/glsa-200410-20.xml
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0888
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0889


Solution: 
    All GPdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-0.132-r2"
    All KDE users should upgrade to the latest version of kdegraphics:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdegraphics-3.3.0-r2"
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/koffice-1.3.3-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-30] GPdf, KPDF, KOffice: Vulnerabilities in included xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GPdf, KPDF, KOffice: Vulnerabilities in included xpdf');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/koffice", unaffected: make_list("ge 1.3.4-r1", "rge 1.3.3-r2"), vulnerable: make_list("lt 1.3.4-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.8.0-r2", "rge 0.132-r2"), vulnerable: make_list("lt 2.8.0-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.3.1-r2", "rge 3.3.0-r2", "rge 3.2.3-r2"), vulnerable: make_list("lt 3.3.1-r2")
)) { security_warning(0); exit(0); }

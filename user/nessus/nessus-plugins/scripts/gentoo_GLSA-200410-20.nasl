# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15539);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200410-20");
 script_cve_id("CVE-2004-0888", "CVE-2004-0889");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-20
(Xpdf, CUPS: Multiple integer overflows)


    Chris Evans discovered multiple integer overflow issues in Xpdf.
  
Impact

    An attacker could entice an user to open a specially-crafted PDF file,
    potentially resulting in execution of arbitrary code with the rights of the
    user running Xpdf. By enticing an user to directly print the PDF file to a
    CUPS printer, an attacker could also crash the CUPS spooler or execute
    arbitrary code with the rights of the CUPS spooler, which is usually the
    "lp" user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0888
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0889


Solution: 
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.00-r5"
    All CUPS users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.1.20-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-20] Xpdf, CUPS: Multiple integer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, CUPS: Multiple integer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.00-r5"), vulnerable: make_list("le 3.00-r4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.1.20-r5"), vulnerable: make_list("le 1.1.20-r4")
)) { security_warning(0); exit(0); }

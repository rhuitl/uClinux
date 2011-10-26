# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16066);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-24");
 script_cve_id("CVE-2004-1125");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-24
(Xpdf, GPdf: New integer overflows)


    A new integer overflow issue was discovered in Xpdf\'s
    Gfx::doImage() function.
  
Impact

    An attacker could entice an user to open a specially-crafted PDF
    file, potentially resulting in execution of arbitrary code with the
    rights of the user running Xpdf or GPdf.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1125
    http://www.idefense.com/application/poi/display?id=172&type=vulnerabilities&flashstatus=true


Solution: 
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.00-r7"
    All GPdf users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-2.8.1-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-24] Xpdf, GPdf: New integer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, GPdf: New integer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.00-r7"), vulnerable: make_list("le 3.00-r6")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.8.1-r1"), vulnerable: make_list("le 2.8.1")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16400);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-09");
 script_cve_id("CVE-2004-0994");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-09
(xzgv: Multiple overflows)


    Multiple overflows have been found in the image processing code of
    xzgv, including an integer overflow in the PRF parsing code
    (CVE-2004-0994).
  
Impact

    An attacker could entice a user to open or browse a
    specially-crafted image file, potentially resulting in the execution of
    arbitrary code with the rights of the user running xzgv.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0994
    http://www.idefense.com/application/poi/display?id=160&type=vulnerabilities&flashstatus=true


Solution: 
    All xzgv users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/xzgv-0.8-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-09] xzgv: Multiple overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xzgv: Multiple overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/xzgv", unaffected: make_list("ge 0.8-r1"), vulnerable: make_list("le 0.8")
)) { security_warning(0); exit(0); }

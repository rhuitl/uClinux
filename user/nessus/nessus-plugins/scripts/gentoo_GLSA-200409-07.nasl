# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14661);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200409-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-07
(xv: Buffer overflows in image handling)


    Multiple buffer overflow and integer handling vulnerabilities have been
    discovered in xv\'s image processing code. These vulnerabilities have been
    found in the xvbmp.c, xviris.c, xvpcx.c and xvpm.c source files.
  
Impact

    An attacker might be able to embed malicious code into an image, which
    would lead to the execution of arbitrary code under the privileges of the
    user viewing the image.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/372345/2004-08-15/2004-08-21/0
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0802


Solution: 
    All xv users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=media-gfx/xv-3.10a-r7"
    # emerge ">=media-gfx/xv-3.10a-r7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-07] xv: Buffer overflows in image handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xv: Buffer overflows in image handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-gfx/xv", unaffected: make_list("ge 3.10a-r7"), vulnerable: make_list("lt 3.10a-r7")
)) { security_warning(0); exit(0); }

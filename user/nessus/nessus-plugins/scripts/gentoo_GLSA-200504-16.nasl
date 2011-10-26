# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18088);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-16");
 script_cve_id("CVE-2005-0753");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-16
(CVS: Multiple vulnerabilities)


    Alen Zukich has discovered several serious security issues in CVS,
    including at least one buffer overflow (CVE-2005-0753), memory leaks
    and a NULL pointer dereferencing error. Furthermore when launching
    trigger scripts CVS includes a user controlled directory.
  
Impact

    An attacker could exploit these vulnerabilities to cause a Denial of
    Service or execute arbitrary code with the permissions of the CVS
    pserver or the authenticated user (depending on the connection method
    used).
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0753


Solution: 
    All CVS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-util/cvs-1.11.20"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-16] CVS: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CVS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-util/cvs", unaffected: make_list("ge 1.11.20"), vulnerable: make_list("lt 1.11.20")
)) { security_hole(0); exit(0); }

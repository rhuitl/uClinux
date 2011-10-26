# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21774);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-28");
 script_cve_id("CVE-2006-2195");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-28
(Horde Web Application Framework: XSS vulnerability)


    Michael Marek discovered that the Horde Web Application Framework
    performs insufficient input sanitizing.
  
Impact

    An attacker could exploit these vulnerabilities to execute arbitrary
    scripts running in the context of the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2195


Solution: 
    All horde users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-3.1.1-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-28] Horde Web Application Framework: XSS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde Web Application Framework: XSS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 3.1.1-r1"), vulnerable: make_list("lt 3.1.1-r1")
)) { security_warning(0); exit(0); }

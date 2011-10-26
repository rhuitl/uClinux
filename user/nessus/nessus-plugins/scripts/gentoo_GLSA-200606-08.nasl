# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21681);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-08");
 script_cve_id("CVE-2006-2667", "CVE-2006-2702");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-08
(WordPress: Arbitrary command execution)


    rgod discovered that WordPress insufficiently checks the format of
    cached username data.
  
Impact

    An attacker could exploit this vulnerability to execute arbitrary
    commands by sending a specially crafted username. As of Wordpress 2.0.2
    the user data cache is disabled by default.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2667
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2702


Solution: 
    All WordPress users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-2.0.3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-08] WordPress: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'WordPress: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 2.0.3"), vulnerable: make_list("lt 2.0.3")
)) { security_hole(0); exit(0); }

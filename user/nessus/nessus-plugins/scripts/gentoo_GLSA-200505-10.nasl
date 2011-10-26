# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18269);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-10
(phpBB: Cross-Site Scripting Vulnerability)


    phpBB is vulnerable to a cross-site scripting vulnerability due to
    improper sanitization of user supplied input. Coupled with poor
    validation of BBCode URLs which may be included in a forum post, an
    unsuspecting user may follow a posted link triggering the
    vulnerability.
  
Impact

    Successful exploitation of the vulnerability could cause arbitrary
    scripting code to be executed in the browser of a user.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.securityfocus.com/bid/13344/info/
    http://securitytracker.com/id?1013918


Solution: 
    All phpBB users should upgrade to the latest version:
    emerge --sync
    emerge --ask --oneshot --verbose ">=www-apps/phpBB-2.0.15"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-10] phpBB: Cross-Site Scripting Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpBB: Cross-Site Scripting Vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpBB", unaffected: make_list("ge 2.0.15"), vulnerable: make_list("lt 2.0.15")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20822);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-14");
 script_cve_id("CVE-2006-0224");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-14
(LibAST: Privilege escalation)


    Michael Jennings discovered an exploitable buffer overflow in the
    configuration engine of LibAST.
  
Impact

    The vulnerability can be exploited to gain escalated privileges if the
    application using LibAST is setuid/setgid and passes a specifically
    crafted filename to LibAST\'s configuration engine.
  
Workaround

    Identify all applications linking against LibAST and verify they are
    not setuid/setgid.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0224


Solution: 
    All users should upgrade to the latest version and run revdep-rebuild:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/libast-0.7"
    # revdep-rebuild
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-14] LibAST: Privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LibAST: Privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-libs/libast", unaffected: make_list("ge 0.7"), vulnerable: make_list("lt 0.7")
)) { security_hole(0); exit(0); }

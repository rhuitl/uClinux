# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20280);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-01");
 script_cve_id("CVE-2005-3962");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-01
(Perl: Format string errors can lead to code execution)


    Jack Louis discovered a new way to exploit format string errors in
    Perl that could lead to the execution of arbitrary code. This is
    perfomed by causing an integer wrap overflow in the efix variable
    inside the function Perl_sv_vcatpvfn. The proposed fix closes that
    specific exploitation vector to mitigate the risk of format string
    programming errors in Perl. This fix does not remove the need to fix
    such errors in Perl code.
  
Impact

    Perl applications making improper use of printf functions (or
    derived functions) using untrusted data may be vulnerable to the
    already-known forms of Perl format string exploits and also to the
    execution of arbitrary code.
  
Workaround

    Fix all misbehaving Perl applications so that they make proper use
    of the printf and derived Perl functions.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3962
    http://www.dyadsecurity.com/perl-0002.html
    http://www.securityfocus.com/archive/1/418460/30/30


Solution: 
    All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-01] Perl: Format string errors can lead to code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Perl: Format string errors can lead to code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/perl", unaffected: make_list("ge 5.8.7-r3", "rge 5.8.6-r8"), vulnerable: make_list("lt 5.8.7-r3")
)) { security_hole(0); exit(0); }

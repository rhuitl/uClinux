# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16414);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-23");
 script_cve_id("CVE-2005-0021", "CVE-2005-0022");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-23
(Exim: Two buffer overflows)


    Buffer overflows have been found in the host_aton() function
    (CVE-2005-0021) as well as in the spa_base64_to_bits() function
    (CVE-2005-0022), which is part of the SPA authentication code.
  
Impact

    A local attacker could trigger the buffer overflow in host_aton()
    by supplying an illegal IPv6 address with more than 8 components, using
    a command line option. The second vulnerability could be remotely
    exploited during SPA authentication, if it is enabled on the server.
    Both buffer overflows can potentially lead to the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.exim.org/mail-archives/exim-announce/2005/msg00000.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0021
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0022


Solution: 
    All Exim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-mta/exim-4.43-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-23] Exim: Two buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Exim: Two buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-mta/exim", unaffected: make_list("ge 4.43-r2"), vulnerable: make_list("lt 4.43-r2")
)) { security_hole(0); exit(0); }

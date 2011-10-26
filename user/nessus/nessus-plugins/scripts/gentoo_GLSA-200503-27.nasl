# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17588);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200503-27");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-27
(Xzabite dyndnsupdate: Multiple vulnerabilities)


    Toby Dickenson discovered that dyndnsupdate suffers from multiple
    overflows.
  
Impact

    A remote attacker, posing as a dyndns.org server, could execute
    arbitrary code with the rights of the user running dyndnsupdate.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    Currently, there is no released version of dyndnsupdate that
    contains a fix for these issues. The original xzabite.org distribution
    site is dead, the code contains several other problems and more secure
    alternatives exist, such as the net-dns/ddclient package. Therefore,
    the dyndnsupdate package has been hard-masked prior to complete removal
    from Portage, and current users are advised to unmerge the package:
    # emerge --unmerge net-misc/dyndnsupdate
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-27] Xzabite dyndnsupdate: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xzabite dyndnsupdate: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/dyndnsupdate", unaffected: make_list(), vulnerable: make_list("le 0.6.15")
)) { security_warning(0); exit(0); }

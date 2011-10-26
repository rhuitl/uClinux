# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15725);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200411-24");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-24
(BNC: Buffer overflow vulnerability)


    Leon Juranic discovered that BNC fails to do proper bounds
    checking when checking server response.
  
Impact

    An attacker could exploit this to cause a Denial of Service and
    potentially execute arbitary code with the permissions of the user
    running BNC.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://gotbnc.com/changes.html
    http://security.lss.hr/en/index.php?page=details&ID=LSS-2004-11-03


Solution: 
    All BNC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-irc/bnc-2.9.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-24] BNC: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BNC: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-irc/bnc", unaffected: make_list("ge 2.9.1"), vulnerable: make_list("lt 2.9.1")
)) { security_hole(0); exit(0); }

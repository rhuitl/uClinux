# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21711);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-18
(PAM-MySQL: Multiple vulnerabilities)


    A flaw in handling the result of pam_get_item() as well as further
    unspecified flaws were discovered in PAM-MySQL.
  
Impact

    By exploiting the mentioned flaws an attacker can cause a Denial of
    Service and thus prevent users that authenticate against PAM-MySQL from
    logging into a machine. There is also a possible additional attack
    vector with more malicious impact that has not been confirmed yet.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://pam-mysql.sourceforge.net/News/


Solution: 
    All PAM-MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-auth/pam_mysql-0.7_rc1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-18] PAM-MySQL: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PAM-MySQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-auth/pam_mysql", unaffected: make_list("ge 0.7_rc1"), vulnerable: make_list("lt 0.7_rc1")
)) { security_warning(0); exit(0); }

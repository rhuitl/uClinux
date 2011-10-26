# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14542);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-09
(MoinMoin: Group ACL bypass)


    MoinMoin contains a bug in the code handling administrative group ACLs. A
    user created with the same name as an administrative group gains the
    privileges of the administrative group.
  
Impact

    If an administrative group called AdminGroup existed an attacker could
    create a user called AdminGroup and gain the privileges of the group
    AdminGroup. This could lead to unauthorized users gaining administrative
    access.
  
Workaround

    For every administrative group with special privileges create a user with
    the same name as the group.
  
References:
    http://sourceforge.net/tracker/index.php?func=detail&aid=948103&group_id=8482&atid=108482
    http://www.osvdb.org/6704


Solution: 
    All users should upgrade to the latest available version of MoinMoin, as
    follows:
    # emerge sync
    # emerge -pv ">=net-ww/moinmoin-1.2.2"
    # emerge ">=net-ww/moinmoin-1.2.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-09] MoinMoin: Group ACL bypass");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MoinMoin: Group ACL bypass');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/moinmoin", unaffected: make_list("ge 1.2.2"), vulnerable: make_list("le 1.2.1")
)) { security_warning(0); exit(0); }

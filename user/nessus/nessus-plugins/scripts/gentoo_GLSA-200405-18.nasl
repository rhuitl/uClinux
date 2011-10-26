# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14504);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200405-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-18
(Buffer Overflow in Firebird)


    A buffer overflow exists in three Firebird binaries (gds_inet_server,
    gds_lock_mgr, and gds_drop) that is exploitable by setting a large value to
    the INTERBASE environment variable.
  
Impact

    An attacker could control program execution, allowing privilege escalation
    to the UID of Firebird, full access to Firebird databases, and trojaning
    the Firebird binaries. An attacker could use this to compromise other user
    or root accounts.
  
Workaround

    There is no known workaround.
  
References:
    http://securityfocus.com/bid/7546/info/
     http://sourceforge.net/tracker/?group_id=9028&atid=109028&func=detail&aid=739480


Solution: 
    All users should upgrade to the latest version of Firebird:
    # emerge sync
    # emerge -pv ">=dev-db/firebird-1.5"
    # emerge ">=dev-db/firebird-1.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-18] Buffer Overflow in Firebird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Buffer Overflow in Firebird');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/firebird", unaffected: make_list("ge 1.5"), vulnerable: make_list("lt 1.5")
)) { security_hole(0); exit(0); }

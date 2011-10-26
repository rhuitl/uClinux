# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14568);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-12");
 script_xref(name: "OSVDB", value: "8382");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-12
(Gaim: MSN protocol parsing function buffer overflow)


    Sebastian Krahmer of the SuSE Security Team has discovered a remotely
    exploitable buffer overflow vulnerability in the code handling MSN protocol
    parsing.
  
Impact

    By sending a carefully-crafted message, an attacker may execute arbitrary
    code with the permissions of the user running Gaim.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Gaim.
  
References:
    http://www.osvdb.org/displayvuln.php?osvdb_id=8382


Solution: 
    All Gaim users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/gaim-0.81-r1"
    # emerge ">=net-im/gaim-0.81-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-12] Gaim: MSN protocol parsing function buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: MSN protocol parsing function buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 0.81-r1"), vulnerable: make_list("le 0.81")
)) { security_warning(0); exit(0); }

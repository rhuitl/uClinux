# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14459);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200403-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-08
(oftpd DoS vulnerability)


    Issuing a port command with a number higher than 255 causes the server to
    crash.  The port command may be issued before any authentication takes
    place, meaning the attacker does not need to know a valid username and
    password in order to exploit this vulnerability.
  
Impact

    This exploit causes a denial of service.
  
Workaround

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected package.
  
References:
    http://www.time-travellers.org/oftpd/oftpd-dos.html


Solution: 
     All users should upgrade to the current version of the affected package:
    # emerge sync
    # emerge -pv ">=net-ftp/oftpd-0.3.7"
    # emerge ">=net-ftp/oftpd-0.3.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-08] oftpd DoS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'oftpd DoS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-ftp/oftpd", unaffected: make_list("ge 0.3.7"), vulnerable: make_list("le 0.3.6")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14447);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200402-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200402-03
(Monkeyd Denial of Service vulnerability)


    A bug in the URI processing of incoming requests allows for a Denial of
    Service to be launched against the webserver, which may cause the server
    to crash or behave sporadically.
  
Impact

    Although there are no public exploits known for bug, users are recommended
    to upgrade to ensure the security of their infrastructure.
  
Workaround

    There is no immediate workaround; a software upgrade is
    required. The vulnerable function in the code has been rewritten.
  
References:
    http://cvs.sourceforge.net/viewcvs.py/monkeyd/monkeyd/src/utils.c?r1=1.3&r2=1.4


Solution: 
    All users are recommended to upgrade monkeyd to 0.8.2:
    # emerge sync
    # emerge -pv ">=net-www/monkeyd-0.8.2"
    # emerge ">=net-www/monkeyd-0.8.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200402-03] Monkeyd Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Monkeyd Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/monkeyd", unaffected: make_list("ge 0.8.2"), vulnerable: make_list("lt 0.8.2")
)) { security_warning(0); exit(0); }

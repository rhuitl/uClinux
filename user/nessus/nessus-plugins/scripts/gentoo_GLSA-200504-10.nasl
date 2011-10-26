# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18043);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200504-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-10
(Gld: Remote execution of arbitrary code)


    dong-hun discovered several buffer overflows in server.c, as well
    as several format string vulnerabilities in cnf.c.
  
Impact

    An attacker could exploit this vulnerability to execute arbitrary
    code with the permissions of the user running Gld, the default user
    being root.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://securitytracker.com/alerts/2005/Apr/1013678.html


Solution: 
    All Gld users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-filter/gld-1.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-10] Gld: Remote execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gld: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-filter/gld", unaffected: make_list("ge 1.5"), vulnerable: make_list("le 1.4")
)) { security_hole(0); exit(0); }

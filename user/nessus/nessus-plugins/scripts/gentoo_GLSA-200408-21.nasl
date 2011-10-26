# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14577);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-21");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-21
(Cacti: SQL injection vulnerability)


    Cacti is vulnerable to a SQL injection attack where an attacker may inject
    SQL into the Username field.
  
Impact

    An attacker could compromise the Cacti service and potentially execute
    programs with the permissions of the user running Cacti. Only systems with
    php_flag magic_quotes_gpc set to Off are vulnerable. By default, Gentoo
    Linux installs PHP with this option set to On.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Cacti.
  
References:
    http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0717.html


Solution: 
    All users should upgrade to the latest available version of Cacti, as
    follows:
    # emerge sync
    # emerge -pv ">=net-analyzer/cacti-0.8.5a-r1"
    # emerge ">=net-analyzer/cacti-0.8.5a-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-21] Cacti: SQL injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cacti: SQL injection vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/cacti", unaffected: make_list("ge 0.8.5a-r1"), vulnerable: make_list("le 0.8.5a")
)) { security_warning(0); exit(0); }

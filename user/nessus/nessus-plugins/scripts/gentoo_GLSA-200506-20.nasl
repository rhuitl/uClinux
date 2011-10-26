# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18547);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200506-20");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-20
(Cacti: Several vulnerabilities)


    Cacti fails to properly sanitize input which can lead to SQL injection
    as well as PHP file inclusion.
  
Impact

    An attacker could potentially exploit the file inclusion to execute
    arbitrary code with the permissions of the web server. An attacker
    could exploit the SQL injection to gain information from the database.
    Only systems with register_globals set to "On" are vulnerable to the
    file inclusion bugs. Gentoo Linux ships with register_globals set to
    "Off" by default.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cacti.net/release_notes_0_8_6e.php
    http://www.idefense.com/application/poi/display?id=267&type=vulnerabilities&flashstatus=false
    http://www.idefense.com/application/poi/display?id=266&type=vulnerabilities&flashstatus=false
    http://www.idefense.com/application/poi/display?id=265&type=vulnerabilities&flashstatus=false


Solution: 
    All Cacti users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/cacti-0.8.6e"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-20] Cacti: Several vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cacti: Several vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/cacti", unaffected: make_list("ge 0.8.6e"), vulnerable: make_list("lt 0.8.6e")
)) { security_hole(0); exit(0); }

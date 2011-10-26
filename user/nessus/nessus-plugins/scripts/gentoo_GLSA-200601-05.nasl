# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20415);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-05");
 script_cve_id("CVE-2005-3656");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-05
(mod_auth_pgsql: Multiple format string vulnerabilities)


    The error logging functions of mod_auth_pgsql fail to validate
    certain strings before passing them to syslog, resulting in format
    string vulnerabilities.
  
Impact

    An unauthenticated remote attacker could exploit these
    vulnerabilities to execute arbitrary code with the rights of the user
    running the Apache2 server by sending specially crafted login names.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3656
    http://www.frsirt.com/english/advisories/2006/0070


Solution: 
    All mod_auth_pgsql users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/mod_auth_pgsql-2.0.3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-05] mod_auth_pgsql: Multiple format string vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'mod_auth_pgsql: Multiple format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/mod_auth_pgsql", unaffected: make_list("ge 2.0.3"), vulnerable: make_list("lt 2.0.3")
)) { security_hole(0); exit(0); }

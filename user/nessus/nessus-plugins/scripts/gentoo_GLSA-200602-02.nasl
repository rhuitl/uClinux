# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20873);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-02");
 script_cve_id("CVE-2006-0410");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-02
(ADOdb: PostgresSQL command injection)


    Andy Staudacher discovered that ADOdb does not properly sanitize
    all parameters.
  
Impact

    By sending specifically crafted requests to an application that
    uses ADOdb and a PostgreSQL backend, an attacker might exploit the flaw
    to execute arbitrary SQL queries on the host.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0410


Solution: 
    All ADOdb users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/adodb-4.71"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-02] ADOdb: PostgresSQL command injection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ADOdb: PostgresSQL command injection');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/adodb", unaffected: make_list("ge 4.71"), vulnerable: make_list("lt 4.71")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16445);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-08");
 script_cve_id("CVE-2005-0227", "CVE-2005-0244", "CVE-2005-0245", "CVE-2005-0246");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-08
(PostgreSQL: Multiple vulnerabilities)


    PostgreSQL\'s contains several vulnerabilities:
    John Heasman discovered that the LOAD extension is vulnerable to
    local privilege escalation (CVE-2005-0227).
    It is possible to bypass the EXECUTE permission check for functions
    (CVE-2005-0244).
    The PL/PgSQL parser is vulnerable to heap-based buffer overflow
    (CVE-2005-0244).
    The intagg contrib module is vulnerable to a Denial of Service
    (CVE-2005-0246).
  
Impact

    An attacker could exploit this to execute arbitrary code with the
    privileges of the PostgreSQL server, bypass security restrictions and
    crash the server.
  
Workaround

    There is no know workaround at this time.
  
References:
    http://archives.postgresql.org/pgsql-announce/2005-02/msg00000.php
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0227
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0244
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0245
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0246


Solution: 
    All PostgreSQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/postgresql-7.4.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-08] PostgreSQL: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("rge 7.4.7", "ge 8.0.1"), vulnerable: make_list("lt 8.0.1")
)) { security_warning(0); exit(0); }

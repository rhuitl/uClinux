# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16460);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-19");
 script_cve_id("CVE-2005-0247");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-19
(PostgreSQL: Buffer overflows in PL/PgSQL parser)


    PostgreSQL is vulnerable to several buffer overflows in the
    PL/PgSQL parser.
  
Impact

    A remote attacker could send a malicious query resulting in the
    execution of arbitrary code with the permissions of the user running
    PostgreSQL.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0247


Solution: 
    All PostgreSQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/postgresql-7.4.7-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-19] PostgreSQL: Buffer overflows in PL/PgSQL parser");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Buffer overflows in PL/PgSQL parser');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("ge 8.0.1-r1", "rge 7.4.7-r1", "rge 7.3.9-r1"), vulnerable: make_list("lt 8.0.1-r1")
)) { security_hole(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15606);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200411-03");
 script_cve_id("CVE-2004-0940");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-03
(Apache 1.3: Buffer overflow vulnerability in mod_include)


    A possible buffer overflow exists in the get_tag() function of
    mod_include.c.
  
Impact

    If Server Side Includes (SSI) are enabled, a local attacker may be able to
    run arbitrary code with the rights of an httpd child process by making use
    of a specially-crafted document with malformed SSI.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0940
    http://www.apacheweek.com/features/security-13


Solution: 
    All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/apache-1.3.32-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-03] Apache 1.3: Buffer overflow vulnerability in mod_include");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 1.3: Buffer overflow vulnerability in mod_include');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 1.3.32-r1"), vulnerable: make_list("lt 1.3.32-r1")
)) { security_warning(0); exit(0); }

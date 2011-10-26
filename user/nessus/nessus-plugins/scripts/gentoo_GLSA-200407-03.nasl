# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14536);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200407-03");
 script_cve_id("CVE-2004-0493");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-03
(Apache 2: Remote denial of service attack)


    A bug in the protocol.c file handling header lines will cause Apache to
    allocate memory for header lines starting with TAB or SPACE.
  
Impact

    An attacker can exploit this vulnerability to perform a Denial of Service
    attack by causing Apache to exhaust all memory. On 64 bit systems with more
    than 4GB of virtual memory a possible integer signedness error could lead
    to a buffer based overflow causing Apache to crash and under some
    circumstances execute arbitrary code as the user running Apache, usually
    "apache".
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version:
  
References:
    http://www.guninski.com/httpd1.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0493


Solution: 
    Apache 2 users should upgrade to the latest version of Apache:
    # emerge sync
    # emerge -pv ">=net-www/apache-2.0.49-r4"
    # emerge ">=net-www/apache-2.0.49-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-03] Apache 2: Remote denial of service attack");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2: Remote denial of service attack');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 2.0.49-r4", "lt 2"), vulnerable: make_list("le 2.0.49-r3")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15693);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-18");
 script_cve_id("CVE-2004-0942");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-18
(Apache 2.0: Denial of Service by memory consumption)


    Chintan Trivedi discovered a vulnerability in Apache httpd 2.0 that is caused by improper enforcing of the field length limit in the header-parsing code.
  
Impact

    By sending a large amount of specially-crafted HTTP GET requests a remote attacker could cause a Denial of Service of the targeted system.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0942
    http://www.apacheweek.com/features/security-20


Solution: 
    All Apache 2.0 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/apache-2.0.52-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-18] Apache 2.0: Denial of Service by memory consumption");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2.0: Denial of Service by memory consumption');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 2.0.52-r1", "lt 2.0"), vulnerable: make_list("lt 2.0.52-r1")
)) { security_warning(0); exit(0); }

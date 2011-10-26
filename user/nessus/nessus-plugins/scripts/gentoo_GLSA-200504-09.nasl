# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18031);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-09");
 script_cve_id("CVE-2005-0390");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-09
(Axel: Vulnerability in HTTP redirection handling)


    A possible buffer overflow has been reported in the HTTP
    redirection handling code in conn.c.
  
Impact

    A remote attacker could exploit this vulnerability by setting up a
    malicious site and enticing a user to connect to it. This could
    possibly lead to the execution of arbitrary code with the permissions
    of the user running Axel.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0390


Solution: 
    All Axel users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/axel-1.0b"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-09] Axel: Vulnerability in HTTP redirection handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Axel: Vulnerability in HTTP redirection handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/axel", unaffected: make_list("ge 1.0b"), vulnerable: make_list("lt 1.0b")
)) { security_warning(0); exit(0); }

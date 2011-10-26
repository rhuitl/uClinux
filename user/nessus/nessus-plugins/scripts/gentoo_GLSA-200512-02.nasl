# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20281);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-02
(Webmin, Usermin: Format string vulnerability)


    Jack Louis discovered that the Webmin and Usermin "miniserv.pl"
    web server component is vulnerable to a Perl format string
    vulnerability. Login with the supplied username is logged via the Perl
    "syslog" facility in an unsafe manner.
  
Impact

    A remote attacker can trigger this vulnerability via a specially
    crafted username containing format string data. This can be exploited
    to consume a large amount of CPU and memory resources on a vulnerable
    system, and possibly to execute arbitrary code of the attacker\'s choice
    with the permissions of the user running Webmin.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3912
    http://www.dyadsecurity.com/webmin-0001.html


Solution: 
    All Webmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/webmin-1.250"
    All Usermin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/usermin-1.180"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-02] Webmin, Usermin: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin, Usermin: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.250"), vulnerable: make_list("lt 1.250")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.180"), vulnerable: make_list("lt 1.180")
)) { security_hole(0); exit(0); }

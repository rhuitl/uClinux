# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14481);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200404-16");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-16
(Multiple new security vulnerabilities in monit)


    Monit has several vulnerabilities in its HTTP interface : a buffer overflow
    vulnerability in the authentication handling code and a off-by-one error in
    the POST method handling code.
  
Impact

    An attacker may exploit the off-by-one error to crash the Monit daemon and
    create a denial of service condition, or cause a buffer overflow that would
    allow arbitrary code to be executed with root privileges.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
References:
    http://www.tildeslash.com/monit/secadv_20040305.txt


Solution: 
    Monit users should upgrade to version 4.2.1 or later:
    # emerge sync
    # emerge -pv ">=app-admin/monit-4.2.1"
    # emerge ">=app-admin/monit-4.2.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-16] Multiple new security vulnerabilities in monit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple new security vulnerabilities in monit');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/monit", unaffected: make_list("ge 4.2.1"), vulnerable: make_list("le 4.2")
)) { security_hole(0); exit(0); }

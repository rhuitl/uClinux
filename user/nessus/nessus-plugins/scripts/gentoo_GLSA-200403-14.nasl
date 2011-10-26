# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14465);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200403-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-14
(Multiple Security Vulnerabilities in Monit)


    A denial of service may occur due to Monit not sanitizing remotely supplied
    HTTP parameters before passing them to memory allocation functions. This
    could allow an attacker to cause an unexpected condition that could lead to
    the Monit daemon crashing.
    An overly long http request method may cause a buffer overflow due to Monit
    performing insufficient bounds checking when handling HTTP requests.
  
Impact

    An attacker may crash the Monit daemon to create a denial of service
    condition or cause a buffer overflow that would allow arbitrary code to be
    executed with root privileges.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
References:
    http://www.securityfocus.com/bid/9098
    http://www.securityfocus.com/bid/9099


Solution: 
    Monit users should upgrade to version 4.2 or later:
    # emerge sync
    # emerge -pv ">=app-admin/monit-4.2"
    # emerge ">=app-admin/monit-4.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-14] Multiple Security Vulnerabilities in Monit");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple Security Vulnerabilities in Monit');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/monit", unaffected: make_list("ge 4.2"), vulnerable: make_list("le 4.1")
)) { security_hole(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14705);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-15
(Webmin, Usermin: Multiple vulnerabilities in Usermin)


    There is an input validation bug in the webmail feature of Usermin.
    Additionally, the Webmin and Usermin installation scripts write to
    /tmp/.webmin without properly checking if it exists first.
  
Impact

    The first vulnerability allows a remote attacker to inject arbitrary shell
    code in a specially-crafted e-mail. This could lead to remote code
    execution with the privileges of the user running Webmin or Usermin.
    The second could allow local users who know Webmin or Usermin is going to
    be installed to have arbitrary files be overwritten by creating a symlink
    by the name /tmp/.webmin that points to some target file, e.g. /etc/passwd.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/12488/
    http://www.webmin.com/uchanges.html


Solution: 
    All Usermin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-admin/usermin-1.090"
    # emerge ">=app-admin/usermin-1.090"
    All Webmin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-admin/webmin-1.160"
    # emerge ">=app-admin/webmin-1.160"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-15] Webmin, Usermin: Multiple vulnerabilities in Usermin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin, Usermin: Multiple vulnerabilities in Usermin');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.090"), vulnerable: make_list("lt 1.090")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.160"), vulnerable: make_list("lt 1.160")
)) { security_warning(0); exit(0); }

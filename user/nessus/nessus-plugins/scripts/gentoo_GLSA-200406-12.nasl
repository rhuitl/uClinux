# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14523);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-12
(Webmin: Multiple vulnerabilities)


    Webmin contains two security vulnerabilities. One allows any user to view
    the configuration of any module and the other could allow an attacker to
    lock out a valid user by sending an invalid username and password.
  
Impact

    An authenticated user could use these vulnerabilities to view the
    configuration of any module thus potentially obtaining important knowledge
    about configuration settings. Furthermore an attacker could lock out
    legitimate users by sending invalid login information.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/bid/10474
    http://www.webmin.com/changes-1.150.html


Solution: 
    All Webmin users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-admin/app-admin/webmin-1.150"
    # emerge ">=app-admin/app-admin/webmin-1.150"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-12] Webmin: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.150"), vulnerable: make_list("le 1.140-r1")
)) { security_warning(0); exit(0); }

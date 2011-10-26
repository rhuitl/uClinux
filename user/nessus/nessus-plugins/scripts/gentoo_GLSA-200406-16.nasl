# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14527);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200406-16");
 script_cve_id("CVE-2004-0492");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-16
(Apache 1.3: Buffer overflow in mod_proxy)


    A bug in the proxy_util.c file may lead to a remote buffer overflow. To
    trigger the vulnerability an attacker would have to get mod_proxy to
    connect to a malicous server which returns an invalid (negative)
    Content-Length.
  
Impact

    An attacker could cause a Denial of Service as the Apache child handling
    the request, which will die and under some circumstances execute arbitrary
    code as the user running Apache, usually "apache".
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version:
  
References:
    http://www.guninski.com/modproxy1.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0492


Solution: 
    Apache 1.x users should upgrade to the latest version of Apache:
    # emerge sync
    # emerge -pv ">=net-www/apache-1.3.31-r2"
    # emerge ">=net-www/apache-1.3.31-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-16] Apache 1.3: Buffer overflow in mod_proxy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 1.3: Buffer overflow in mod_proxy');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 1.3.31-r2"), vulnerable: make_list("le 1.3.31-r1")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14558);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200408-02");
 script_cve_id("CVE-2004-0591");
 script_xref(name: "CERT", value: "CA-2000-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-02
(Courier: Cross-site scripting vulnerability in SqWebMail)


    Luca Legato found that SqWebMail is vulnerable to a cross-site scripting
    (XSS) attack. An XSS attack allows an attacker to insert malicious code
    into a web-based application. SqWebMail doesn\'t filter appropriately data
    coming from message headers before displaying them.
  
Impact

    By sending a carefully crafted message, an attacker can inject and execute
    script code in the victim\'s browser window. This allows to modify the
    behaviour of the SqWebMail application, and/or leak session information
    such as cookies to the attacker.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Courier.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0591
    http://www.cert.org/advisories/CA-2000-02.html


Solution: 
    All Courier users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=mail-mta/courier-0.45.6.20040618"
    # emerge ">=mail-mta/courier-0.45.6.20040618"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-02] Courier: Cross-site scripting vulnerability in SqWebMail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Courier: Cross-site scripting vulnerability in SqWebMail');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-mta/courier", unaffected: make_list("ge 0.45.6.20040618"), vulnerable: make_list("le 0.45.6")
)) { security_warning(0); exit(0); }

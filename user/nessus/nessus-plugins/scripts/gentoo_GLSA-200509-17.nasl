# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19816);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-17");
 script_cve_id("CVE-2005-3042");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-17
(Webmin, Usermin: Remote code execution through PAM authentication)


    Keigo Yamazaki discovered that the miniserv.pl webserver, used in
    both Webmin and Usermin, does not properly validate authentication
    credentials before sending them to the PAM (Pluggable Authentication
    Modules) authentication process. The default configuration shipped with
    Gentoo does not enable the "full PAM conversations" option and is
    therefore unaffected by this flaw.
  
Impact

    A remote attacker could bypass the authentication process and run
    any command as the root user on the target server.
  
Workaround

    Do not enable "full PAM conversations" in the Authentication
    options of Webmin and Usermin.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3042
    http://www.lac.co.jp/business/sns/intelligence/SNSadvisory_e/83_e.html


Solution: 
    All Webmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/webmin-1.230"
    All Usermin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-admin/usermin-1.160"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-17] Webmin, Usermin: Remote code execution through PAM authentication");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Webmin, Usermin: Remote code execution through PAM authentication');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.160"), vulnerable: make_list("lt 1.160")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-admin/webmin", unaffected: make_list("ge 1.230"), vulnerable: make_list("lt 1.230")
)) { security_hole(0); exit(0); }

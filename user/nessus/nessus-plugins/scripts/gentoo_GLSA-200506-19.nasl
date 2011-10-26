# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18545);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200506-19");
 script_cve_id("CVE-2005-1769");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-19
(SquirrelMail: Several XSS vulnerabilities)


    SquirrelMail is vulnerable to several cross-site scripting issues,
    most reported by Martijn Brinkers.
  
Impact

    By enticing a user to read a specially-crafted e-mail or using a
    manipulated URL, an attacker can execute arbitrary scripts running in
    the context of the victim\'s browser. This could lead to a compromise of
    the user\'s webmail account, cookie theft, etc.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.squirrelmail.org/security/issue/2005-06-15
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1769


Solution: 
    All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/squirrelmail-1.4.4"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-19] SquirrelMail: Several XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SquirrelMail: Several XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.4", "lt 1.4.0"), vulnerable: make_list("lt 1.4.4")
)) { security_warning(0); exit(0); }

# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20264);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-20");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-20
(Horde Application Framework: XSS vulnerability)


    The Horde Team reported a potential XSS vulnerability. Horde fails
    to properly escape error messages which may lead to displaying
    unsanitized error messages via Notification_Listener::getMessage()
  
Impact

    By enticing a user to read a specially-crafted e-mail or using a
    manipulated URL, an attacker can execute arbitrary scripts running in
    the context of the victim\'s browser. This could lead to a compromise of
    the user\'s browser content.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3570
    http://lists.horde.org/archives/announce/2005/000231.html


Solution: 
    All Horde Application Framework users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/horde-2.2.9"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-20] Horde Application Framework: XSS vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde Application Framework: XSS vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/horde", unaffected: make_list("ge 2.2.9"), vulnerable: make_list("lt 2.2.9")
)) { security_warning(0); exit(0); }

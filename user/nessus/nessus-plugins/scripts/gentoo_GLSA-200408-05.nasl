# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14561);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-05
(Opera: Multiple new vulnerabilities)


    Multiple vulnerabilities have been found in the Opera web browser. Opera
    fails to deny write access to the "location" browser object. An
    attacker can overwrite methods in this object and gain script access to any
    page that uses one of these methods. Furthermore, access to file:// URLs is
    possible even from pages loaded using other protocols. Finally, spoofing a
    legitimate web page is still possible, despite the fixes announced in GLSA
    200407-15.
  
Impact

    By enticing an user to visit specially crafted web pages, an attacker can
    read files located on the victim\'s file system, read emails written or
    received by M2, Opera\'s mail program, steal cookies, spoof URLs, track user
    browsing history, etc.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://www.opera.com/linux/changelogs/754/
    http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1056.html
    http://www.greymagic.com/security/advisories/gm008-op/


Solution: 
    All Opera users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-www/opera-7.54"
    # emerge ">=net-www/opera-7.54"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-05] Opera: Multiple new vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple new vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/opera", unaffected: make_list("ge 7.54"), vulnerable: make_list("le 7.53")
)) { security_warning(0); exit(0); }

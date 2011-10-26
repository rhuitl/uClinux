# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20815);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-13
(Gallery: Cross-site scripting vulnerability)


    Peter Schumacher discovered that Gallery fails to sanitize the
    fullname set by users, possibly leading to a cross-site scripting
    vulnerability.
  
Impact

    By setting a specially crafted fullname, an attacker can inject
    and execute script code in the victim\'s browser window and potentially
    compromise the user\'s gallery.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://gallery.menalto.com/page/gallery_1_5_2_release


Solution: 
    All Gallery users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/gallery-1.5.2"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-13] Gallery: Cross-site scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 1.5.2"), vulnerable: make_list("lt 1.5.2")
)) { security_warning(0); exit(0); }

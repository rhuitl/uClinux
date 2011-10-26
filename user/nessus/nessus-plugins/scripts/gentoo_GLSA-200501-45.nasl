# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-45.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16436);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200501-45");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-45
(Gallery: Cross-site scripting vulnerability)


    Rafel Ivgi has discovered a cross-site scripting vulnerability where
    the \'username\' parameter is not properly sanitized in \'login.php\'.
  
Impact

    By sending a carefully crafted URL, an attacker can inject and execute
    script code in the victim\'s browser window, and potentially compromise
    the user\'s gallery.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://gallery.menalto.com/modules.php?op=modload&name=News&file=article&sid=149
    http://secunia.com/advisories/13887/


Solution: 
    All Gallery users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/gallery-1.4.4_p6"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-45] Gallery: Cross-site scripting vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gallery: Cross-site scripting vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/gallery", unaffected: make_list("ge 1.4.4_p6"), vulnerable: make_list("lt 1.4.4_p6")
)) { security_warning(0); exit(0); }

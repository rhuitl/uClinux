# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22286);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-24");
 script_cve_id("2006-4089");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-24
(AlsaPlayer: Multiple buffer overflows)


    AlsaPlayer contains three buffer overflows: in the function that
    handles the HTTP connections, the GTK interface, and the CDDB querying
    mechanism.
  
Impact

    An attacker could exploit the first vulnerability by enticing a user to
    load a malicious URL resulting in the execution of arbitrary code with
    the permissions of the user running AlsaPlayer.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-4089


Solution: 
    AlsaPlayer has been masked in Portage pending the resolution of these
    issues. AlsaPlayer users are advised to uninstall the package until
    further notice:
    # emerge --ask --unmerge "media-sound/alsaplayer"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-24] AlsaPlayer: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'AlsaPlayer: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/alsaplayer", unaffected: make_list(), vulnerable: make_list("le 0.99.76-r3")
)) { security_warning(0); exit(0); }

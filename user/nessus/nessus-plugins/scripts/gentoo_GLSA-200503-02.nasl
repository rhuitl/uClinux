# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17249);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-02");
 script_cve_id("CVE-2005-0258", "CVE-2005-0259");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-02
(phpBB: Multiple vulnerabilities)


    It was discovered that phpBB contains a flaw in the session
    handling code and a path disclosure bug. AnthraX101 discovered that
    phpBB allows local users to read arbitrary files, if the "Enable remote
    avatars" and "Enable avatar uploading" options are set (CVE-2005-0259).
    He also found out that incorrect input validation in
    "usercp_avatar.php" and "usercp_register.php" makes phpBB vulnerable to
    directory traversal attacks, if the "Gallery avatars" setting is
    enabled (CVE-2005-0258).
  
Impact

    Remote attackers can exploit the session handling flaw to gain
    phpBB administrator rights. By providing a local and a remote location
    for an avatar and setting the "Upload Avatar from a URL:" field to
    point to the target file, a malicious local user can read arbitrary
    local files. By inserting "/../" sequences into the "avatarselect"
    parameter, a remote attacker can exploit the directory traversal
    vulnerability to delete arbitrary files. A flaw in the "viewtopic.php"
    script can be exploited to expose the full path of PHP scripts.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0258
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0259
    http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=267563


Solution: 
    All phpBB users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpBB-2.0.13"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-02] phpBB: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpBB: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpBB", unaffected: make_list("ge 2.0.13"), vulnerable: make_list("lt 2.0.13")
)) { security_warning(0); exit(0); }

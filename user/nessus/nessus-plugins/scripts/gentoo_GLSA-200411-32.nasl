# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-32.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15826);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200411-32");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-32
(phpBB: Remote command execution)


    phpBB contains a vulnerability in the highlighting code and
    several vulnerabilities in the username handling code.
  
Impact

    An attacker can exploit the highlighting vulnerability to access
    the PHP exec() function without restriction, allowing them to run
    arbitrary commands with the rights of the web server user (for example
    the apache user). Furthermore, the username handling vulnerability
    might be abused to execute SQL statements on the phpBB database.
  
Workaround

    There is a one-line patch which will remediate the remote
    execution vulnerability.
    Locate the following block of code in
    viewtopic.php:
    //
    // Was a highlight request part of the URI?
    //
    $highlight_match = $highlight = \'\';
    if (isset($HTTP_GET_VARS[\'highlight\']))
    {
       // Split words and phrases
       $words = explode(\' \', trim(htmlspecialchars(urldecode($HTTP_GET_VARS[\'highlight\']))));
       for($i = 0; $i < sizeof($words); $i++)
       {
    Replace with the following:
    //
    // Was a highlight request part of the URI?
    //
    $highlight_match = $highlight = \'\';
    if (isset($HTTP_GET_VARS[\'highlight\']))
    {
       // Split words and phrases
       $words = explode(\' \', trim(htmlspecialchars($HTTP_GET_VARS[\'highlight\'])));
       for($i = 0; $i < sizeof($words); $i++)
       {
  
References:
    http://www.phpbb.com/phpBB/viewtopic.php?t=240513


Solution: 
    All phpBB users should upgrade to the latest version to fix all
    known vulnerabilities:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpbb-2.0.11"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-32] phpBB: Remote command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpBB: Remote command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpbb", unaffected: make_list("ge 2.0.11"), vulnerable: make_list("le 2.0.10")
)) { security_hole(0); exit(0); }

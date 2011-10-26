# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22242);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-20");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-20
(Ruby on Rails: Several vulnerabilities)


    The Ruby on Rails developers have corrected some weaknesses in
    action_controller/, relative to the handling of the user input and the
    LOAD_PATH variable. A remote attacker could inject arbitrary entries
    into the LOAD_PATH variable and alter the main Ruby on Rails process.
    The security hole has only been partly solved in version 1.1.5. Version
    1.1.6 now fully corrects it.
  
Impact

    A remote attacker that would exploit these weaknesses might cause a
    Denial of Service of the web framework and maybe inject arbitrary Ruby
    scripts.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://weblog.rubyonrails.org/2006/8/9/rails-1-1-5-mandatory-security-patch-and-other-tidbits
    http://weblog.rubyonrails.org/2006/8/10/rails-1-1-6-backports-and-full-disclosure


Solution: 
    All Ruby on Rails users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-ruby/rails-1.1.6"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-20] Ruby on Rails: Several vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby on Rails: Several vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-ruby/rails", unaffected: make_list("ge 1.1.6"), vulnerable: make_list("lt 1.1.6")
)) { security_hole(0); exit(0); }

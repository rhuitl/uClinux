#TRUSTED 2f8dd26903817f6945f54269495ff64c9b93155999ea46885f898d316d53a521174a025e1a673709e65140d1c0c9ce9989bf454396528736f40d9db1809f7e5fa5fa33631a576487e87936cf90b49043ec1d81ff59777e52980c492fce1d7b4f9ea14946f189224793ed43ecda616f8c93a9d5a7d4149e957ccf05b5b47542a766baee66acfa456251e4b66d47099edc634e886eb19687f87758a5af2e3237d33b95cb57cbf391a5b7bb3b3e3397e6b8e923c39d3ca48d20d34a9834c6ebf8d0987ad14cb14badb6353ae3bcad706e1894da01dda2ea3d09f5f7e80bb2007b26d86452e19e76a4573c75808cb58ceed665876c043154f21adf498654bcf5a2eaa92148df0514b0995c23a8a140c7c904c2f26acf68919f8e2fec6f363aef7fee36c3a12d95b97f78b47b39ecc01a9b7a6d9c11aa8c7eb993336c3f91604da7846b1cd3a1ca4856381372ce229b8ca773bdccbffc7f37171bfdbc25bd54df6f73c38d428dd459e2119fff9bfdfaaa9fed1e173943d989e6f5b3af1d7c15c8e4e0b3bec2a86e73caa509f49851a91fcc621e267359d0cda8de99bd23dfd23d7f7eeed71e15a00985f0a900fac09bb1afc87d630f78883a3d235f369864d603879bdc9e9fbeddfdf61be17cc4c5658ba5e68f72010f79158596a95d82cb1f019b4415a5f68c6ceafc43f348c7435ce9d69fc73f5a60f328b99e988650b8e1ec8ded
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21724);
 script_version ("1.1");
 script_bugtraq_id ( 18382 );
 script_cve_id("CVE-2006-2492");
 name["english"] = "Vulnerability in Microsoft PowerPoint Could Allow Remote Code Execution (916768) (Mac OS X)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft
PowerPoint.

Description :

The remote host is running a version of Microsoft PowerPoint
which is subject to a flaw which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it. Then a bug in
the font parsing handler would result in code execution.

Solution : 

Microsoft has released a set of patches for PowerPoint X and 2004 for 
Mac OS X :

http://www.microsoft.com/technet/security/bulletin/ms06-028.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for PowerPoint 2004 and X";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


include("ssh_func.inc");


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.*", string:uname) )
{
  off2004 = 'cd /Applications/Microsoft\\ Office\\ 2004 && osascript -e \'tell application "Finder" to get {version} of alias "::Microsoft PowerPoint"\' | awk \'{print $1}\'';
  offX    = 'cd /Applications/Microsoft\\ Office\\ X && osascript -e \'tell application "Finder" to get {version} of alias "::Microsoft PowerPoint"\' | awk \'{print $1}\'';

  if ( ! islocalhost() )
  {
   soc = ssh_login_or_reuse_connection();
   if ( ! soc ) exit(0);
   buf = ssh_cmd(socket:soc, cmd:off2004);
   if ( buf !~ "^11" )
    buf = ssh_cmd(socket:soc, cmd:offX);
   ssh_close_connection();
  }
  else
  {
  buf = pread(cmd:"bash", argv:make_list("bash", "-c", off2004));
  if ( buf !~ "^11" )
    buf = pread(cmd:"bash", argv:make_list("bash", "-c", offX));
  }


 if ( buf =~ "^(10\.|11\.)" )
	{
	  vers = split(buf, sep:'.', keep:FALSE);
	  # < 10.1.7
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_hole(0);
	  else
          # < 11.2.4
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 4 ) ) ) security_hole(0);
	} 
}

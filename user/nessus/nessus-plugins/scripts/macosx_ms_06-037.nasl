#TRUSTED 073c69f9fbbfc44daa1410c902f454641d692fe34086d49c4412ccb8ba1b9822a6c9701547e9f7e1e632fed47a9c1e2a74860f62603b8d95dedf4e4020cd2e5fde4a01e95146b4ddee46961a27e552e54ca3b05a7c925e0b5b1ffdfbfe225f3e9c353238dd768befaf7469d758661bd175db89249338da07388ca1188dbf00ce73cba1f2e6443e7c38e0b2c135894217079d690de38906e1bb143be2dcf6d3cfbb0083e58258249cb315f19fbaa71be58ffef2f21eacd1eb9543811e381989f6e5008f3a6c7d888d34929dea6d17dbd534de44f512c62cc5e8ae9d003323f22fc0bc61cd478a3d00b093c8bb4813de918dad898de5fa53e4c72bd36baf035f1060a0984e730ef833da56f06e20baf3362d0679688b35d0e71547bc97d52e3e7e5ea3e068d7a572af99be6b19d92cf2144eb219e7427f8846dd053a5c90a7a32f3ace79c6bfec8e664ea317609b946810ea44e95109547a6f716c117add73ba7e121bb7863c58539bbb93a6c91eb896ec8601634c56a47423bb2bf8484d44bdec6c343a2ba1d891099a3192e43ae30391d4c417eb2e9fa1901e0f12abf8dd39ef92018896de6742fa95e310d1bbdbf6038bb3e761a287db6a193477a2c5788139e1caf254e15d0847728fd505a542b7d63146959e490cf48b0926d7a1afca0e681001be9439d366d777ce561f70144aada6e9af62f0bf1e3c53b2047fc2483006
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22025);
 script_bugtraq_id(18938, 18915, 18913, 18912, 18911, 18890, 18888, 18886, 18885);
 script_version ("1.0");
 script_cve_id("CVE-2006-1301", "CVE-2006-1302", "CVE-2006-1304", "CVE-2006-1306", "CVE-2006-1308", "CVE-2006-1309", "CVE-2006-2388", "CVE-2006-3059");
 
 name["english"] = "Vulnerabilities in Microsoft Excel and Office Could Allow Remote Code Execution (917284/917285) (Mac OS X)";
 

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft
Excel.

Description :

The remote host is running a version of Microsoft Office
which is subject to various flaws which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it with
Microsoft Excel or another Office application.

Solution : 

Microsoft has released a set of patches for Office for Mac OS X :

http://www.microsoft.com/technet/security/bulletin/ms06-037.mspx
http://www.microsoft.com/technet/security/bulletin/ms06-038.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Excel 2004 and X";
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
  off2004 = 'cd /Applications/Microsoft\\ Office\\ 2004 && osascript -e \'tell application "Finder" to get {version} of alias "::Microsoft Excel"\' | awk \'{print $1}\'';
  offX    = 'cd /Applications/Microsoft\\ Office\\ X && osascript -e \'tell application "Finder" to get {version} of alias "::Microsoft Excel"\' | awk \'{print $1}\'';

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
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 7 ) ) ) security_warning(0);
	  else
          # < 11.2.5
	  if ( int(vers[0]) == 11 && ( int(vers[1]) < 2  || ( int(vers[1]) == 2 && int(vers[2]) < 5 ) ) ) security_warning(0);
	} 
}

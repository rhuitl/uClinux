#TRUSTED 3ab9f2b4b951bee452126ec5d37c732f2bbc19a3fb88baf6a13c88112549194e7900cbeb056e25b5ddbdc1a9b0103d6cccecc63580244492eb54397051c96a05eab7ebd700f7ebb14ba7d632b8f3438bf623beda7d7d5693957e5d36c1cd9f0cb0ef2197b2a2304b018f817455195a70a55af51f35970569a585138ae15e8c869a2055f53c1e0ae4f98110e24d24ddfa2333ad3144fd0dc402666b85d11322ae3396eda848f2ba270af882742cb4bd85a611625a338d589ce3d72990ed17c3b8cd3848e91b796ab62cfae9a589665be00d0a4bf02a9b90fa4e42a9180f8b0c6158e664e6461b0bb6edd0271ffb22352f3359c0c56ecd0c3943f257927c395fce544b83db507e71a9a5094025e5cb6abdafaa95d1457fe3756ba042130dda2cac273a10edc2626c9bc32b3c7b7e0b0114243b365c01a1bf4f1ff9663f59f155c7697db0fc0915e50978b80181b11cef4153eb2d26963e7519470167928e3f95e640e60a2e829215b50fcb6554341555283492e33a1d51768c68f969104f4556f3ba50e7ff99bda8f239d0cbb1ba160751d95cdca6a5741db0d1d588f0a60c779ac1a6dad172187f98a91545157721b1e051385d383fde2b3287c246801564965cc5f4b7e3240b9236bdb426dd031f0b6cca1db6da4df7cdeb58726cc42d5f636151fec3c862a89322299c09256b2861cb975820048e1417fdcd9777d8168b3122
#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22539);
 script_version ("1.0");
 if ( NASL_LEVEL >= 3000 ) 
   script_cve_id("CVE-2006-3435", 
		"CVE-2006-3876", 
		"CVE-2006-3877", 
		"CVE-2006-4694", 
		"CVE-2006-2387", 
		"CVE-2006-3431",
		"CVE-2006-3867",
		"CVE-2006-3875",
		"CVE-2006-3647",
		"CVE-2006-3651",
		"CVE-2006-4534",
		"CVE-2006-4693",
		"CVE-2006-3434",
		"CVE-2006-3650",
		"CVE-2006-3864",
		"CVE-2006-3868"
	);
 
 name["english"] = "Vulnerabilities in Microsoft Office Allow Remote Code Execution (924163,924164,924554,922581) (Mac OS X)";
 

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft
Office.

Description :

The remote host is running a version of Microsoft Office
which is subject to various flaws which may allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it with
Microsoft Word, Excel, PowerPoint or another Office application.

Solution : 

Microsoft has released a set of patches for Office for Mac OS X :

http://www.microsoft.com/technet/security/Bulletin/MS06-058.mspx
http://www.microsoft.com/technet/security/Bulletin/MS06-059.mspx
http://www.microsoft.com/technet/security/Bulletin/MS06-060.mspx
http://www.microsoft.com/technet/security/Bulletin/MS06-062.mspx


Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Office 2004 and X";
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
  off2004 = 'cd /Applications/Microsoft\\ Office\\ 2004/Office && osascript -e \'tell application "Finder" to get {version} of alias "::Microsoft Component Plugin"\' | awk \'{print $1}\'';
  offX    = 'cd /Applications/Microsoft\\ Office\\ X/Office && osascript -e \'tell application "Finder" to get {version} of alias "::Microsoft Component Plugin"\' | awk \'{print $1}\'';

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
	  # < 10.1.8
	  if ( int(vers[0]) == 10 && ( int(vers[1]) < 1  || ( int(vers[1]) == 1 && int(vers[2]) < 8 ) ) )  security_hole(0);
	  else
          # < 11.3.0
	  if ( int(vers[0]) == 11 && int(vers[1]) < 3  ) security_hole(0);
	} 
}

#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11952);
 script_version("$Revision: 1.6 $");

 name["english"] = "FlashPlayer files reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host contains an application that is affected by remote
file disclosure.

Description :

The remote host is running a version of flash player older than 7.0.19.0.

This version can be abused in conjunction with several flaws in the web
browser to read local files on this system.

To exploit this flaw, an attacker would need to lure a user of this system
into visiting a rogue website containing a malicious flash applet.

Solution :

Upgrade to version 7.0.19.0 or newer.

See also :

http://www.macromedia.com/devnet/security/security_zone/mpsb03-08.html

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of the remote flash plugin";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("flash_player_overflows.nasl");
 script_require_keys("MacromediaFlash/version");
 exit(0);
}


ver = get_kb_item("MacromediaFlash/version");

if (!isnull(ver))
{
  if (ereg(pattern:"^([0-6]\..*|7\.0\.([0-9]\.|1[0-8]\.))", string:ver))
    security_warning(get_kb_item ("SMB/transport"));
}


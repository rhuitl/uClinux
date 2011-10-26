#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
#  From: "Berend-Jan Wever" <SkyLined@edup.tudelft.nl>
#  To: <bugtraq@securityfocus.com>, <full-disclosure@lists.netsys.com>,
#        "Windows NTBugtraq Mailing List" <NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM>,
#        "vulnwatch" <vulnwatch@vulnwatch.org>
#  Date: Mon, 7 Apr 2003 18:47:57 +0200
#  Subject: [VulnWatch] Coppermine Photo Gallery remote compromise


if(description)
{
 script_id(11524);
 script_bugtraq_id(7300);
 script_version ("$Revision: 1.9 $");


 name["english"] = "Coppermine Gallery Remote Command Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Coppermine Gallery - a set of PHP scripts
designed to handle galleries of pictures.

This product has a vulnerability which allows an attacker to upload
a rogue jpeg file which may contain PHP commands, and therefore may
obtain a shell on this host.

Solution : Upgrade to Coppermine 1.1 beta 2
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of db_input.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("coppermine_gallery_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

kb = get_kb_list("www/" + port + "/coppermine_photo_gallery");
if ( isnull(kb) ) exit(0);

foreach k ( kb )
{
 version = split(k, sep:" under ", keep:0);
 if ( ereg(pattern:"^v?(0\.|1\.(0\.|1 (devel|Beta 1)))", string:version[0], icase:TRUE) )
 	{
	security_hole(port);
	exit(0);
	}
}


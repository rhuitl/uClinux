#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15531);
 script_bugtraq_id(11485);
 script_version ("$Revision: 1.1 $");


 name["english"] = "Coppermine Gallery Voting Restriction Failure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Coppermine Gallery - a set of PHP scripts
designed to handle galleries of pictures.

This product has a vulnerability which allows an attacker to cast
multiple votes for a picture, provided he did not enable cookies
on his host.


Solution : Upgrade to Coppermine 1.3.3 or newer
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of db_input.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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
 if ( ereg(pattern:"^v?(0\.|1\.(0\.|1 (devel|Beta [12])|[0-2]\.|3\.[0-2]))", string:version[0], icase:TRUE) )
 	{
	security_note(port);
	exit(0);
	}
}


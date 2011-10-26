#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11778);
 script_version("$Revision: 1.9 $");
# script_cve_id("CVE-MAP-NOMATCH");
 name["english"] = "Web Server hosting copyrighted material";
 script_name(english:name["english"]);

 desc["english"] = "
This script determines if the remote web server hosts
potentially copyright-infringing files, such as mp3,
wav, avi or asf files.";


 script_description(english:desc["english"]);

 summary["english"] = "Looks for *.(mp3,avi,asf,mpg,wav,ogg)";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_dependencie("httpver.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

function check(port, sfx)
{
 list = get_kb_list(string("www/", port, "/content/extensions/", sfx));
 if(isnull(list))return make_list();
 else list = make_list(list);
 return list;
}


 
port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


files = make_list();
files = make_list(files, check(port:port, sfx:"mp3"));
files = make_list(files, check(port:port, sfx:"MP3"));
files = make_list(files, check(port:port, sfx:"asf"));
files = make_list(files, check(port:port, sfx:"ASF"));
files = make_list(files, check(port:port, sfx:"mpg"));
files = make_list(files, check(port:port, sfx:"MPG"));
files = make_list(files, check(port:port, sfx:"mpeg"));
files = make_list(files, check(port:port, sfx:"MPEG"));
files = make_list(files, check(port:port, sfx:"ogg"));
files = make_list(files, check(port:port, sfx:"OGG"));
files = make_list(files, check(port:port, sfx:"wma"));
files = make_list(files, check(port:port, sfx:"WMA"));

report = NULL;

num_suspects = 0;
foreach f (files)
{
 if( strlen(f) )
 	{
	 report += ' - ' + f + '\n';
	 num_suspects ++;
	 if( num_suspects >= 40 )
	 { 
	  report += ' - ... (more) ...\n';
	  break;
	 }
	}
}

if (!isnull(report))
{
 r = 
'Here is a list of files which have been found on the remote web server.
Some of these files may contain copyrighted materials, such as commercial
movies or music files. 

If any of this file actually contains copyrighted material and if
they are freely swapped around, your organization might be held liable
for copyright infringement by associations such as the RIAA or the MPAA.

' + report + '

Solution : Delete all the copyrighted files';

 security_warning(port:port, data:r);
}

#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a PHP-based content management system. 

Description :

The remote host is running PostNuke, a content manager system written
in PHP. 

See also :

http://www.postnuke.com

Risk factor: 

None";


if(description)
{
 script_id(15721);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "PostNuke Detection";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Detects the presence of PostNuke";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = "";




function check(loc)
{
 req = http_get(item:string(loc, "/index.php?module=Navigation"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('PostNuke' >< r && egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r, icase:1) )
 {
	version_str = egrep(pattern:"<meta name=.generator. content=.PostNuke", string:r, icase:1);
	version_str = chomp(version_str);
 	version = ereg_replace(pattern:".*content=.PostNuke ([0-9.]*) .*", string:version_str, replace:"\1");
	if ( version == version_str ) version = "unknown";
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/postnuke",
		    value:version + " under " + loc );
	
	dirs += "  - " + version + " under '" + loc + "'\n";
 }
}

#foreach dir (cgi_dirs())
foreach dir (make_list("/vulns/postnuke"))
{
 check(loc:dir);
 if (dirs && !thorough_tests) break;
}

if ( dirs ) 
{
  info = string(
    "The following version(s) of PostNuke were detected :\n",
    "\n",
    dirs
  );
  desc["english"] += '\n\nPlugin output :\n\n' + info;

  security_note(port:port, data:desc["english"]);
}


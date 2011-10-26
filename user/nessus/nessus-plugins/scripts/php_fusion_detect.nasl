#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a content management system written in
PHP. 

Description :

This script determines if PHP-Fusion is installed on the remote host
and, if so, stores its location in the KB. 

PHP-Fusion is a light-weight, open-source content management system
written in PHP. 

See also : 

http://www.php-fusion.co.uk/

Risk factor :

None";


if(description)
{
 script_id(16335);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "PHP-Fusion Detection";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the location of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

info = NULL;

if (thorough_tests) dirs = make_list("/fusion", "/php-files", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 req = http_get(item:string(dir, "/news.php"), port:port);
 debug_print("req='", req, "'.");
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 debug_print("res='", res, "'.");
 if( res == NULL )exit(0);

 if (egrep(pattern:"Powered by.*PHP-Fusion", string:res))
 {
   pat = ".*PHP-Fusion.*v([0-9][.,][0-9.,]+) .* 20[0-9][0-9]-20[0-9][0-9]";
   matches = egrep(pattern:pat, string:res);
   foreach match (split(matches)) {
     match = chomp(match);
     ver = eregmatch(pattern:pat, string:match);
     if (!isnull(ver)) {
       ver = ver[1];
       break;
     }
   }
   if (isnull(ver)) ver = "unknown";
   debug_print("ver='", ver, "'.");
   if ( dir == "" ) dir = "/";

   set_kb_item(name:"www/" + port + "/php-fusion", value:ver + " under " + dir);
   info += ' - ' + ver + ' under ' + dir + '\n';

   if (!thorough_tests) break;
 }
}

if ( info )
{
  desc["english"] += '\n\nPlugin output :\n\n' + 
    'The remote web site is running the following version(s) of this software :\n\n' +
    info;
  security_note(port:port, data:desc["english"]);
}

# (C) Tenable Network Security
#
#
# This plugin uses the data collected by webmirror.nasl to try
# to download a backup file old each CGI (as in foo.php -> foo.php.old)

desc["english"] = "
Synopsis :

It is possible to download the source code of several scripts
on the remote web server

Description :

By appending various suffixes (ie: .old, .bak, ~, etc...) to the
names of several pages on the remote host, it seems possible to
download the source code of these scripts.

You should ensure these files do no contain any sensitive information, such
as credentials to connect to a database.

Solution :

Delete these files.

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";



if(description)
{
 script_id(11411);
 script_version ("$Revision: 1.16 $");
 
 name["english"] = "Backup CGIs download";
 script_name(english:name["english"]);
 



 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to download the remote CGIs";
 
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!port || !get_port_state(port))exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

list = make_list();

t = get_kb_list(string("www/", port, "/cgis"));
if(!isnull(t)){
	foreach c (t)
	s = strstr(c, " - ");
	c = c - s;
	list = make_list(list, c);
	}


t = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/php"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/php3"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/php4"));
if(!isnull(t))list = make_list(list, t);

t = get_kb_list(string("www/", port, "/content/extensions/cfm"));
if(!isnull(t))list = make_list(list, t);


list = make_list(list, "/.htaccess");


exts = make_list(".old", ".bak", "~", ".2", ".copy", ".tmp", ".swp", ".swp");
prefixes = make_list("", "",   "",  "",   "",      "",     "",      ".");

oldfiles = make_list();
foreach f (list)
{
 this_oldfiles = make_list();
 num_match = 0;
 for ( i = 0; exts[i]; i ++ )
 {
   file = ereg_replace(pattern:"(.*)/([^/]*)$", replace:"\1/" + prefixes[i] + "\2" + exts[i], string:f);
   if(is_cgi_installed_ka(port:port, item:file))
   {
    file2 = ereg_replace(pattern:"(.*)/([^/]*)$", replace:"\1/" + prefixes[i] + "\2" + exts[i], string:string(f, rand()));
    if(!is_cgi_installed_ka(port:port, item:file2))
    {
     this_oldfiles = make_list(this_oldfiles, file);
     num_match ++;
    }
   }
 }
 # Avoid false positives
 if(num_match < 5) oldfiles = make_list(oldfiles, this_oldfiles);
}

report = NULL;

foreach f (oldfiles)
{
  report += f + '\n';
}

if( report != NULL )
  {
    report = desc["english"]  + '\n\nPlugin output :\n\nIt s possible to read the following files :\n' + report;
    security_warning(port:port, data:report);
  }

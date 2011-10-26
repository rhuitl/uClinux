#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15530);
 script_version ("$Revision: 1.1 $");


 name["english"] = "Coppermine Gallery Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin determines if the Coppermine Gallery Photo Album is installed
on the remote web server and stores its location in the KB.

Risk factor : None";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Coppermine Gallery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


locations = make_list();
flag = 0;

foreach dir (make_list("/demo"))
{
   req = http_get(item:string(dir, "/db_input.php"), port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if( res == NULL ) exit(0);
    if ( "<!--Coppermine Photo Gallery" >< res )
    {
      line = egrep(pattern:"<!--Coppermine Photo Gallery.*", string:res);
      version = ereg_replace(pattern:".*Coppermine Photo Gallery (.*)-->.*", 
			     string:line,
			     replace:"\1");

 report += '\n\nRisk factor: Low';

      set_kb_item(name:"www/" + port + "/coppermine_photo_gallery",
		  value:version + " under " + dir);
      locations = make_list(locations, dir);
      flag ++;
    }
}


if ( flag )
{
 report = "
Coppermine Gallery, a PHP-based photo album, in installed under
the following location";
 if ( flag > 1 ) report += "s";
 report += ' :\n\n';
 foreach dir (locations) 
 {
  report += '  - http://' + get_host_name() + ':' + port + dir + '\n';
 }

 report += '\n\nRisk factor: Low';
 security_note(port:port, data:report);
}

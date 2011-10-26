#
# (C) Tenable Network Security
#
if(description)
{
   script_id(20228);
   script_version ("$Revision: 1.3 $");
   
   name["english"] = "Google Search Appliance Detection";
   script_name(english:name["english"]);
 
   desc["english"] = "
Synopsis :

The remote host is a Google Search Appliance.

Description :

The remote host seems to be a Google Search Appliance. These appliances
are used to index the files contained on an intranet and make them searchable.

Make sure that this appliance can only be accessed by authorized personel or
that the data it indexes is public.

Solution :

Restrict the set of hosts to index in the appliance, if necessary.

Risk factor :

None";

   script_description(english:desc["english"]);
   summary["english"] = "Detects a Google Appliance";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english: "This script is Copyright (C) 2005 Tenable Network Security");
   script_family(english: "General");
   script_dependencie("http_version.nasl");
   script_require_ports("Services/www", 80);
   exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

res = http_get_cache(item:"/", port:port);
if ( ereg(pattern:"^HTTP.* 302 ", string:res) )
{
 if ( egrep(pattern:"^Location: /search\?site=.*&client=.*&output=.*&proxystylesheet=.*&proxycustom=.*", string:res) )
 {

        set_kb_item(
          name:string("www/", port, "/google_search_appliance"),
          value:TRUE
        );
	security_note(port);
 }
}

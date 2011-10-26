#
# This buggy script was written by Laurent FACQ (@u-bordeaux.fr)
#
#
# Based on :  http://www.phenoelit.de/hp/JetRoot_pl.txt
#       " Phenoelit HP Web JetAdmin 6.5 remote\n".
#       " Linux root and Windows NT/2000 Administrator exploit\n".
#       " by FX of Phenoelit\n".
#       " Research done at BlackHat Singapore 2002\n\n";
#



if(description)
{
    script_id(12227); 
    script_bugtraq_id(9973);
    script_version ("$Revision: 1.5 $");
    name["english"] = "HP Jet Admin 6.5 or less Vulnerability";
    script_name(english:name["english"]);

    desc["english"] = "
The remote HP Web Jetadmin is vulnerable to multiple exploits.  This includes,
but is not limited to, full remote administrative access.  An attacker
can execute code remotely with SYSTEM level (or root) privileges by invoking
the ExecuteFile function.  To further exacerbate this issue, there is working
exploit code for multiple vulnerabilities within this product.

See also :
http://www.phenoelit.de/stuff/HP_Web_Jetadmin_advisory.txt
http://xforce.iss.net/xforce/xfdb/15989

Solution: The issues are resolved in HP Web Jetadmin version 7.5

Risk factor : High";

    script_description(english:desc["english"]);

    summary["english"] = "HP JetAdmin 6.5 or less vulnerability";

    script_summary(english:summary["english"]);

    script_category(ACT_ATTACK);

    script_copyright(english:"facq");

    family["english"] = "General";
    script_family(english:family["english"]);
    script_dependencies("find_service.nes", "http_version.nasl");
    script_require_ports("Services/www", 8000);
    exit(0);
}


include("http_func.inc");

# Check starts here

port = 8000;
if(!get_port_state(port))exit(0);

r = http_send_recv(port:port, data:string("GET /plugins/hpjwja/help/about.hts HTTP/1.0\r\n\r\n"));

if(r == NULL) { 
    #display ("\n\nexit null\n\n"); 
    exit(0); 
}

if((r =~ "HTTP/1.[01] 200") && ("Server: HP-Web-Server" >< r))
{
    r= ereg_replace(pattern:"<b>|</b>", string:r, replace: "<>");
    r= ereg_replace(pattern:"<[^>]+>", string:r, replace: "");
    r= ereg_replace(pattern:"[[:space:]]+", string:r, replace: " ");
    r= ereg_replace(pattern:" <>", string:r, replace: "<>");
    r= ereg_replace(pattern:"<> ", string:r, replace: "<>");

    #display(r); # debug
    #display("\n\n"); # debug

    if (
        (r =~ "<>HP Web JetAdmin Version<>6.5") # tested
        ||
        (r =~ "<>HP Web JetAdmin Version<>6.2") # not tested
        ||
        (r =~ "<>HP Web JetAdmin Version<>7.0") # not tested
        )

    {
        #display("\nhole \n"); # debug
        security_hole(port);
    }
}


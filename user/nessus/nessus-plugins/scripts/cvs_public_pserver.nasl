if(description)
{
 script_id(11384);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Public CVS pserver";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin attempts to log into the remote public CVS pserver
using commonly used accounts, passwords and directory paths.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Logs into the remote CVS server";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_ports("Services/cvspserver", 2401);
 script_dependencies("find_service.nes");
 exit(0);
}

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

function report_lp(port, login, pass, dir)
{
 local_var report;
 
 report = string(
"It was possible to find the public CVS repository of the remote host\n",
"by searching a list of commonly used passwords and CVS repositories\n",
"We found that the remote CVS server is accessible as :\n",
"    User       : ", login, "\n",
"    Pass       : ", scramble(pass:pass), "\n",
"    Repository : ", dir, "\n\n",
"We suggest you disable public CVS access if your developement\n",
"is not meant to be shared by the public.\n",
"\n",
"Risk factor : High");

  security_hole(port:port, data:report);
  exit(0);
}


shifts =  raw_string(
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
  114,120, 53, 79, 96,109, 72,108, 70, 64, 76, 67,116, 74, 68, 87,
  111, 52, 75,119, 49, 34, 82, 81, 95, 65,112, 86,118,110,122,105,
   41, 57, 83, 43, 46,102, 40, 89, 38,103, 45, 50, 42,123, 91, 35,
  125, 55, 54, 66,124,126, 59, 47, 92, 71,115, 78, 88,107,106, 56,
   36,121,117,104,101,100, 69, 73, 99, 63, 94, 93, 39, 37, 61, 48,
   58,113, 32, 90, 44, 98, 60, 51, 33, 97, 62, 77, 84, 80, 85,223,
  225,216,187,166,229,189,222,188,141,249,148,200,184,136,248,190,
  199,170,181,204,138,232,218,183,255,234,220,247,213,203,226,193,
  174,172,228,252,217,201,131,230,197,211,145,238,161,179,160,212,
  207,221,254,173,202,146,224,151,140,196,205,130,135,133,143,246,
  192,159,244,239,185,168,215,144,139,165,180,157,147,186,214,176,
  227,231,219,169,175,156,206,198,129,164,150,210,154,177,134,127,
  182,128,158,208,162,132,167,209,149,241,153,251,237,236,171,195,
  243,233,253,240,194,250,191,155,142,137,245,235,163,242,178,152);
  
  

function scramble(pass)
{
 local_var str;
 str ="";
 
 for(i=0;i<strlen(pass);i++)str += shifts[ord(pass[i])];
 return str;
}


dirs = make_list("/cvsroot", "/cvs", "/cvsroot", "/u/cvs", "/home/ncvs", "/usr/local/cvs");

logins = make_list("anonymous", "anoncvs");
passes   = make_list("anon", "anoncvs", "");

scrambled = make_list();

foreach pass (passes)
{
 pass = scramble(pass:pass); 
 scrambled = make_list(scrambled, pass);
}


foreach dir (dirs)
 foreach login (logins)
  foreach pass (scrambled)
  {
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  req = string("BEGIN AUTH REQUEST\n",
dir, "\n",
login,"\n",
"A", pass,"\n",
"END AUTH REQUEST\n");

  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:4096);
  close(soc);
  if("I LOVE YOU" >< r) # How touching
  {
    if(!get_kb_item(string("cvs/", port, "/login")))
    {
    set_kb_item(name:string("cvs/", port, "/login"), value:login);
    set_kb_item(name:string("cvs/", port, "/pass"), value:pass);
    set_kb_item(name:string("cvs/", port, "/dir"), value:dir);
    }
    report_lp(port:port, login:login, pass:pass, dir:dir);
    exit(0);
  }
 }

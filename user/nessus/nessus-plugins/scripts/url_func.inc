# -*- Fundamental -*-
#
# (C) Tenable Network Security
#
# uri_func.inc
# $Revision: 1.3 $
#


# url_hex2raw is identical to hex2raw from misc_func.inc apart from its name.
function url_hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2) display("url_hex2raw: odd string: ", s, "\n");
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}


# This function takes the string 'estr' encoded per RFC 2396 / 2732 and decodes it.
function urldecode(estr)
{
  local_var ch, len, i, str;

  str = "";
  len = strlen(estr);

  i = 0;
  while (i < len)
  {
    ch = estr[i];
    if (ch == "+") ch = " ";

    if (ch == "%")
    {
      # nb: url_hex2raw() expects only lowercase hex digits!
      str = str + url_hex2raw(s:tolower(substr(estr, i+1, i+2)));
      i += 2;
    }
    else str = str + ch;
    i++;
  }

  return str;
}


global_var HEX_LOWERCASE, HEX_UPPERCASE;

HEX_LOWERCASE = 1;
HEX_UPPERCASE = 2;

# This function takes the string 'str' and encodes it per RFC 2396 / 2732. 
# If specified, 'unreserved' is a string with characters that should not be 
# encoded.
function urlencode(str, unreserved, case)
{
  local_var ch, estr, len, i;

  estr = "";
  len = strlen(str);
  if (isnull(unreserved)) unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]";
  if (isnull(case)) case = HEX_LOWERCASE;

  for (i=0; i<len; i+=1)
  {
    ch = str[i];

    if (ch >< unreserved) estr = estr + ch;
    # the rest are escaped.
    else
    {
      ch = hexstr(ch);
      if (case == HEX_UPPERCASE)
        ch = toupper(ch);
      estr = estr + "%" + ch;
    }
  }

  return estr;
}

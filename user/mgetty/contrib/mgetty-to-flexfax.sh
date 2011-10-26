From quack.kfu.com!nsayer Tue Aug  9 00:05:12 1994
Return-Path: <nsayer@quack.kfu.com>
Received: by greenie.muc.de (/\==/\ Smail3.1.24.1 #24.2)
	id <m0qXcoc-0000GkC@greenie.muc.de>; Tue, 9 Aug 94 00:05 MEST
Received: from quack.kfu.com ([192.216.60.254]) by colin.muc.de with SMTP id <135962(2)>; Tue, 9 Aug 1994 00:04:35 +0200
Received: by quack.kfu.com id AA17510
  (5.65c8/IDA-1.4.4 for gert@greenie.muc.de); Mon, 8 Aug 1994 15:04:20 -0700
From:	Nick Sayer <nsayer@quack.kfu.com>
Message-Id: <199408082204.AA17510@quack.kfu.com>
Subject: g3 to tiff
To:	gert@greenie.muc.de (Gert Doering)
Date:	Tue, 9 Aug 1994 00:04:20 +0200
In-Reply-To: <m0qXaYV-0000b5C@greenie.muc.de> from "Gert Doering" at Aug 8, 94 09:40:18 pm
X-Mailer: ELM [version 2.4 PL22]
Mime-Version: 1.0
Content-Type: text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: 7bit
Content-Length: 1371      
Status: RO

I've done it. It's just fax2tiff from the tiff distribution. The trick
is to add -M to the parameters because the faxes come in little endian.
I also modified it to allow me to add an IMAGEDESCRIPTION tag which
contains the TSI of the sender. This matches what flexfax does, and
let's faxinfo work right. After that, it's just like this:


--- new_fax ---
#! /bin/sh

PATH=/usr/local/bin:/usr/ucb:/bin:/usr/local/lib/mgetty+sendfax:$PATH
export PATH

FILE=/var/spool/fax/recvq/mgetty.$$

hangup=$1 ; shift
id="$1" ; shift
nump=$1 ; shift

if [ $hangup -eq 0 ]; then
	hangup=""
fi

fax2tiff -d "$id" -M -o $FILE $* >/dev/null 2>&1
rm -f $*
chown uucp.uucp $FILE
chmod 600 $FILE

/var/spool/fax/bin/faxrcvd $FILE '?' '?' '?' "$hangup" ttym9

exit 0
---

Normally 'mgetty.$$' would be a bad choice for a filename, but my
faxrcvd script (for flexfax) moves that to a different name anyway.

BTW: You might pass this on to Klaus (his e-mail seems to be /dev/null,
so far as I can tell :-) ): If answer_mode == ANSWER_VOICE (_not_
ANSWER_VOICE | ANSWER_{DATA,FAX} ), it seems silly to even bother
doing "AT+FCLASS=0 A". Might as well just hang up.

-- 
Nick Sayer <nsayer@quack.kfu.com>    | "Don't worry, they'll ride up with
N6QQQ @ N0ARY.#NOCAL.CA.USA.NOAM     | wear."
+1 408 249 9630, log in as 'guest'   | 
URL: http://www.kfu.com/~nsayer/     | -- Are You Being Served?


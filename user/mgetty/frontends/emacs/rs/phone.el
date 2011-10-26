;;; phone.el -- phone number conventions for GNU Emacs.
;;;
;;; Copyright (C) 1995 Ralph Schleicher
;;;
;;; This library is free software; you can redistribute it and/or
;;; modify it under the terms of the GNU Library General Public
;;; License as published by the Free Software Foundation; either
;;; version 2 of the License, or (at your option) any later version.
;;;
;;; This library is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Library General Public License for more details.
;;;
;;; You should have received a copy of the GNU Library General Public
;;; License along with this library; if not, write to the Free
;;; Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
;;;
;;; This file is not part of GNU Emacs.
;;;
;;; Author: Ralph Schleicher <rs@purple.IN-Ulm.DE>
;;; Maintainer: see the `Author' field
;;; Keywords: local comm
;;; Comments: Put something like
;;;
;;; 	(setq phone-number-international-prefix "00"
;;; 	      phone-number-long-distance-prefix "0"
;;; 	      phone-number-country-code "49"
;;; 	      phone-number-area-code "7352")
;;;
;;; into your `site-start.el' file.
;;; Time-stamp: "Wed Nov 15 19:31:48 MET 1995 rs@purple.IN-Ulm.DE"
;;; Code:


(defvar phone-number-international-prefix nil
  "*Phone number prefix for placing an international call.
This is \"00\" for most countries but there are exceptions of the rule.
See the documentation of the phone-number-dial-string function for a
list of known prefixes.")

(defvar phone-number-international-wait nil
  "*A character sequence waiting for the dial tone, \"W\" in many cases.
See the documentation of the phone-number-dial-string function for a
list of countries where this have to be set.")

(defvar phone-number-long-distance-prefix nil
  "*Phone number prefix for placing a long distance call.
Most countries are using \"0\" for this purpose.")

(defvar phone-number-line-prefix nil
  "*Phone number prefix for getting the line.
Set this to a character sequence like \">W\", \"0W\" or \"0,\" if your
modem is not connected to a direct telephone line.  Check your modem
manual for the correct command for getting the line.")

(defvar phone-number-country-code nil
  "*Phone number country code of your state.
Neither put the international phone number prefix nor any extra plus
sign characters in front of the country code!")

(defvar phone-number-area-code nil
  "*Phone number area prefix of your site.
Omit the long distance prefix from this variable -- set it with the
`phone-number-long-distance-prefix'.")

(defun phone-number-dial-string (string)
  "Translate STRING to a phone number suitable for the modem.
Inserts the translated phone number at point if called interactively.
The following table lists the codes known so far:

     Country       | Country |  Intern.  | Long dist.
                   |  code   |  prefix   |   prefix
     --------------+---------+-----------+-----------
     Austria       | AT   43 |  00       |     ?
     Belgium       | BE   32 |  00  wait |     ?
     Switzerland   | CH   41 |  00       |     0
     Germany       | DE   49 |  00       |     0
     Denmark       | DK   45 | 009       |     ?
     Spain         | ES   34 |  07  wait |     ?
     France        | FR   33 |  19  wait |     ?
     Great Britain | GB   44 | 010       |     ?
     Italy         | IT   39 |  00       |     ?
     Luxembourg    | LU  352 |  00       |     ?
     Netherlands   | NL   31 |  09  wait |     ?
     Norway        | NO   47 | 095       |     ?
     Sweden        | SE   46 | 009       |     ?
     USA           | US    1 | 011       |     ?

     ?  Value is unknown.
"
  (interactive "sPhone number: ")
  (let* ((i-regexp (regexp-quote phone-number-international-prefix))
	 (c-regexp (concat i-regexp "[^0-9]*"
			   (regexp-quote phone-number-country-code)))
	 (l-regexp (regexp-quote phone-number-long-distance-prefix))
	 (a-regexp (concat i-regexp "[^0-9]*"
			   (regexp-quote phone-number-area-code))))
    (if (string-match "\\`[^0-9+]+" string)
	(setq string (substring string (match-end 0))))
    (if (string-match (concat "\\`\\(" i-regexp "\\|\\++\\)") string)
	(setq string (concat phone-number-international-prefix
			     (substring string (match-end 0)))))
    (if (string-match (concat "\\`" c-regexp "[^0-9]*") string)
	(progn
	  (setq string (substring string (match-end 0)))
	  (if (not (string-match (concat "\\`" l-regexp) string))
	      (setq string (concat phone-number-long-distance-prefix string)))))
    (if (string-match (concat "\\`" a-regexp "[^0-9]*") string)
	(setq string (substring string (match-end 0))))
    (while (string-match "[^0-9]+" string)
      (setq string (concat (substring string 0 (match-beginning 0))
			   (substring string (match-end 0)))))
    (if (and (stringp phone-number-international-wait)
	     (not (equal phone-number-international-wait ""))
	     (string-match (concat "\\`" i-regexp) string))
	(setq string (concat phone-number-international-prefix
			     phone-number-international-wait
			     (substring string (match-end 0)))))
    (if (and (stringp phone-number-line-prefix)
	     (not (equal phone-number-line-prefix "")))
	(setq string (concat phone-number-line-prefix string)))
    (if (interactive-p)
	(insert string))
    string))

(provide 'phone)


;;; local variables:
;;; truncate-lines: t
;;; end:

;;; phone.el ends here

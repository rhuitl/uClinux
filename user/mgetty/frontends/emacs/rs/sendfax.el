;;; sendfax.el -- fax sending commands for GNU Emacs.
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
;;; Keywords: local comm fax
;;; Comments: Put something like
;;;
;;;	(setq sendfax-package "mgetty")
;;;
;;;	(autoload 'sendfax-buffer "sendfax"
;;;	  "Pass the current buffer to the fax sub-system." t)
;;;	(autoload 'sendfax-region "sendfax"
;;;	  "Send the contents of region to the fax sub-system." t)
;;;
;;; into your `site-start.el' file.  Other customizations have to be
;;; done via `sendfax-send-hook', e.g.,
;;;
;;;	(setq sendfax-send-hook
;;;	      '(lambda ()
;;;		 (setq ps-print-header t
;;;		       ps-header-lines 2
;;;		       ps-left-header (list "(Yoyodyne Inc.)"
;;;					    'user-full-name)
;;;		       ps-right-header (list 'time-stamp-month-dd-yyyy))))
;;;
;;; Read the code of Jim Thompson's Pretty-Good PostScript Generator
;;; if you plan to do such wild things.
;;; Time-stamp: "Wed Nov 15 19:51:02 MET 1995 rs@purple.IN-Ulm.DE"
;;; Code:


(require 'faxutil)

(defvar sendfax-package nil
  "*A string describing your fax sub-system.
The `sendfax' function knows the calling conventions of \"mgetty\"
and \"faxpr\".	The following table describes these packages more
briefly:

     Package | Description
     --------+--------------------------------------------------------
     mgetty  | The mgetty+sendfax package by Gert Doering
	     | <gert@greenie.muc.de>.
     faxpr   | A front-end for mgetty+sendfax with networking support
	     | by Ralph Schleicher <rs@purple.in-ulm.de>.

A value of nil supplies only generic support.")

(defvar sendfax-program nil
  "*Program used to send facsimile messages.
Defaults to \"faxspool\" for the mgetty+sendfax package, \"faxpr\" for
the FAXpr package and \"sendfax\" in any other case.")

(defvar sendfax-switches nil
  "*List of extra arguments when `sendfax-program' is invoked.")

(defvar sendfax-send-hook nil)

(defun sendfax (start end numbers)
  "Send the region between START and END to NUMBERS.
NUMBERS is either a comma separated string or a list of phone numbers
or fax aliases.	 NUMBERS will be read from the mini-buffer if no one
were specified."
  (if (null numbers)
      (let (number)
	(while (progn
		 (setq number (completing-read "Fax to: " fax-aliases))
		 (not (string-match number "\\`[ \t,]*\\'")))
	  (setq numbers (cons number numbers)))
	(setq numbers (nreverse numbers))))
  (if (listp numbers)
      (setq numbers (mapconcat 'identity numbers ", ")))
  (setq numbers (fax-phone-number numbers t))
  (if (null numbers)
      (error "Recipient's phone number is void"))
  (let ((to (car numbers))
	(cc (cdr numbers))
	(ps-lpr-command nil)
	(ps-lpr-switches nil)
	(ps-print-header nil)
	(ps-print-header-frame nil)
	(ps-header-lines 0)
	(ps-left-header nil)
	(ps-right-header nil))
    (if (not (y-or-n-p (if (null cc)
			   (format "Send fax to %s? " to)
			 (format "Send fax to %s with %s to %s? " to
				 (if (= (length cc) 1) "copy" "copies")
				 (mapconcat 'identity cc ", ")))))
	(signal 'quit nil))
    (run-hooks 'sendfax-send-hook)
    (cond ((equal sendfax-package "mgetty")
	   (setq ps-lpr-command (if (boundp 'sendfax-program)
				    sendfax-program
				  "faxspool"))
	   (while numbers
	     (setq ps-lpr-switches (append '("-q") sendfax-switches
					   (list (car numbers) "-"))
		   numbers (cdr numbers))
	     (save-excursion
	       (ps-print-region-with-faces start end))))
	  ((equal sendfax-package "faxpr")
	   (setq ps-lpr-command (if (boundp 'sendfax-program)
				    sendfax-program
				  "faxpr")
		 ps-lpr-switches (append (list "-a" to)
					 (apply 'append
						(mapcar '(lambda (number)
							   (list "-c" number))
							cc))
					 sendfax-switches))
	   (ps-print-region-with-faces start end))
	  (t
	   (setq ps-lpr-command (if (boundp 'sendfax-program)
				    sendfax-program
				  "sendfax")
		 ps-lpr-switches (append sendfax-switches numbers))
	   (ps-print-region-with-faces start end)))))

;;;### autoload
(defun sendfax-buffer ()
  "Pass the current buffer to the fax sub-system.
Don't call this function from a program, use `sendfax' instead."
  (interactive) (sendfax (point-min) (point-max) nil))

;;;### autoload
(defun sendfax-region (start end)
  "Send the contents of region to the fax sub-system.
Don't call this function from a program, use `sendfax' instead."
  (interactive "r") (sendfax start end nil))

(provide 'sendfax)


;;; sendfax.el ends here

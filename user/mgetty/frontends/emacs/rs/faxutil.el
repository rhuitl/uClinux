;;; faxutil.el -- basic fax functions.
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
;;; Comments: Add
;;;
;;;	(autoload 'fax-read-resource-file "faxutil"
;;;	  "Read a fax resource file." t)
;;;	(autoload 'fax-define-fax-alias "faxutil"
;;;	  "Define a fax alias." t)
;;;
;;; to your `site-start.el' file so that the user can define fax
;;; aliases interactively or in `~/.emacs'.
;;; Time-stamp: "Wed Nov 15 19:32:07 MET 1995 rs@purple.IN-Ulm.DE"
;;; Code:


(require 'phone)

(defvar fax-resource-file-name "~/.faxrc"
  "*Name of file for setting resources like fax aliases.")

(defvar fax-aliases nil
  "*Alist of phone number aliases.
Will be initialized from the file `fax-resource-file-name'.  The alias
definitions in the file have the form:

     alias NAME VALUE

See the documentation of the `fax-define-fax-alias' function for more
details about NAME and VALUE.")

;;;### autoload
(defun fax-read-resource-file (&optional file-name)
  "Read a fax resource file.
FILE-NAME defaults to `fax-resource-file-name'.  Only fax aliases of
the form:

     alias NAME VALUE

will be read -- all other things will be ignored."
  (interactive "fRead file: ")
  (setq file-name (expand-file-name (or file-name fax-resource-file-name)))
  (let ((orig-buf (current-buffer))
	(temp-buf nil))
    (unwind-protect
	(let ((case-fold-search nil))
	  (message "Reading %s..." file-name)
	  (setq temp-buf (generate-new-buffer "faxrc"))
	  (buffer-disable-undo temp-buf)
	  (set-buffer temp-buf)
	  (insert-file-contents file-name)
	  (goto-char (point-max))
	  (or (eq (preceding-char) ?\n)
	      (newline))
	  (goto-char (point-min))
	  (while (re-search-forward "^[ \t]*alias[ \t]+" nil t)
	    (re-search-forward "[^ \t\n]+")
	    (let* ((name (buffer-substring (match-beginning 0) (match-end 0)))
		   (start (progn
			    (skip-chars-forward " \t") (point)))
		   (value (progn
			    (end-of-line) (buffer-substring start (point)))))
	      (fax-define-fax-alias name value)))
	  (message "Reading %s...done" file-name))
      (if temp-buf
	  (kill-buffer temp-buf))
      (set-buffer orig-buf))))

;;;### autoload
(defun fax-define-fax-alias (name value)
  "Define NAME as a fax alias for VALUE.
VALUE can be either the final phone number or another alias.  One or
more names have to be separated by commas.  VALUE will be executed in
an inferior shell if the first character of VALUE is a vertical bar.
The output of the shell command replaces the old contents of VALUE."
  (interactive "sDefine fax alias: \nsDefine `%s' as fax alias for: ")
  (setq value (mapconcat (function identity) (fax-phone-number value) ", "))
  (let ((known (assoc name fax-aliases)))
    (if known
	(setcdr known value)
      (setq fax-aliases (cons (cons name value) fax-aliases)))))

(defun fax-phone-number (value &optional resolve)
  "Translate VALUE to a list of phone numbers.
Recursively expand fax aliases if RESOLVE is non-nil.
See `fax-define-fax-alias' for more details about VALUE."
  (if (string-match "\\`[ \t]*|" value)
      (let ((orig-buf (current-buffer))
	    (temp-buf nil))
	(setq value (substring value (match-end 0)))
	(unwind-protect
	    (progn
	      (setq temp-buf (generate-new-buffer "faxsh"))
	      (buffer-disable-undo temp-buf)
	      (set-buffer temp-buf)
	      (if (not (zerop (call-process shell-file-name nil temp-buf nil
					    shell-command-switch value)))
		  (error "Shell command `%s' failed" value))
	      (while (search-forward "\n" nil t)
		(replace-match ", "))
	      (setq value (buffer-string)))
	  (if temp-buf
	      (kill-buffer temp-buf))
	  (set-buffer orig-buf))))
  (let ((result (fax-phone-number-list value)))
    (if resolve
	(let (name alias done)
	  (while result
	    (while (setq name (car result)
			 alias (assoc name fax-aliases))
	      (setq result (nconc (fax-phone-number-list (cdr alias))
				  (cdr result))))
	    (setq result (cdr result))
	    (if (not (assoc name done))
		(setq done (cons (cons name t) done))))
	  (setq result (delete "" (mapcar 'phone-number-dial-string
					  (nreverse (mapcar 'car done)))))))
    result))

(defun fax-phone-number-list (string)
  (if (string-match "\\`[ \t,]+" string)
      (setq string (substring string (match-end 0))))
  (if (string-match "[ \t\n,]+\\'" string)
      (setq string (substring string 0 (match-beginning 0))))
  (let ((result '())
	(start (and (not (equal string "")) 0))
	(len (length string))
	(end nil))
    (while start
      (setq end (string-match "[ \t]*,[ \t,]*" string start)
	    result (cons (substring string start end) result)
	    start (and end (/= (match-end 0) len) (match-end 0))))
    (nreverse result)))

(defvar fax-resources-loaded nil)

(if fax-resources-loaded
    nil
  (fax-read-resource-file)
  (setq fax-resources-loaded t))

(provide 'faxutil)


;;; faxutil.el ends here

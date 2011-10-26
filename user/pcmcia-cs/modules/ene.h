/*
 * ene.h 1.1 2001/02/27 14:55:08
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License
 * at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and
 * limitations under the License.
 *
 * The initial developer of the original code is David A. Hinds
 * <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
 * are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU Public License version 2 (the "GPL"), in which
 * case the provisions of the GPL are applicable instead of the
 * above.  If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use
 * your version of this file under the MPL, indicate your decision by
 * deleting the provisions above and replace them with the notice and
 * other provisions required by the GPL.  If you do not delete the
 * provisions above, a recipient may use your version of this file
 * under either the MPL or the GPL.
 */

#ifndef _LINUX_ENE_H
#define _LINUX_ENE_H

#ifndef PCI_VENDOR_ID_ENE
#define PCI_VENDOR_ID_ENE		0x1524
#endif

#ifndef PCI_DEVICE_ID_ENE_1211
#define PCI_DEVICE_ID_ENE_1211		0x1211
#endif
#ifndef PCI_DEVICE_ID_ENE_1225
#define PCI_DEVICE_ID_ENE_1225		0x1225
#endif
#ifndef PCI_DEVICE_ID_ENE_1410
#define PCI_DEVICE_ID_ENE_1410		0x1410
#endif
#ifndef PCI_DEVICE_ID_ENE_1420
#define PCI_DEVICE_ID_ENE_1420		0x1420
#endif

#define ENE_PCIC_ID \
    IS_ENE1211, IS_ENE1225, IS_ENE1410, IS_ENE1420

#define ENE_PCIC_INFO \
    { "ENE 1211", IS_TI|IS_CARDBUS, ID(ENE, 1211) }, \
    { "ENE 1225", IS_TI|IS_CARDBUS, ID(ENE, 1225) }, \
    { "ENE 1410", IS_TI|IS_CARDBUS, ID(ENE, 1410) }, \
    { "ENE 1420", IS_TI|IS_CARDBUS, ID(ENE, 1420) }

#endif /* _LINUX_ENE_H */

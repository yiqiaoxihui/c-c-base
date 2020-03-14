#ifndef __CHARSETS_H__
#define __CHARSETS_H__

#include "Base.h"

/*
 * Translation tables that map the upper 128 code points in single-byte
 * "extended ASCII" character encodings to Unicode code points in the
 * Basic Multilingual Plane.
 */

/* Table for windows-1250 */
extern const gunichar2 charset_table_cp1250[0x80];
/* Table for windows-1251 */
extern const gunichar2 charset_table_cp1251[0x80];
/* Table for windows-1252 */
extern const gunichar2 charset_table_cp1252[0x80];

/* Tables for ISO-8859-X */
extern const gunichar2 charset_table_iso_8859_2[0x80];
extern const gunichar2 charset_table_iso_8859_3[0x80];
extern const gunichar2 charset_table_iso_8859_4[0x80];
extern const gunichar2 charset_table_iso_8859_5[0x80];
extern const gunichar2 charset_table_iso_8859_6[0x80];
extern const gunichar2 charset_table_iso_8859_7[0x80];
extern const gunichar2 charset_table_iso_8859_8[0x80];
extern const gunichar2 charset_table_iso_8859_9[0x80];
extern const gunichar2 charset_table_iso_8859_10[0x80];
extern const gunichar2 charset_table_iso_8859_11[0x80];
extern const gunichar2 charset_table_iso_8859_13[0x80];
extern const gunichar2 charset_table_iso_8859_14[0x80];
extern const gunichar2 charset_table_iso_8859_15[0x80];
extern const gunichar2 charset_table_iso_8859_16[0x80];

/* Tables for Mac character sets */
extern const gunichar2 charset_table_mac_roman[0x80];

/* Tables for DOS code pages */
extern const gunichar2 charset_table_cp437[0x80];
extern const gunichar2 charset_table_cp855[0x80];
extern const gunichar2 charset_table_cp866[0x80];




guint8 * get_ascii_string(/*wmem_allocator_t *scope, */const guint8 *ptr, gint length);
guint8 * get_ucs_2_string(/*wmem_allocator_t *scope,*/ const guint8 *ptr, gint length, const guint encoding);
gchar * get_ascii_7bits_string(/*wmem_allocator_t *scope,*/ const guint8 *ptr,const gint bit_offset, gint no_of_chars);
guint8 *get_unichar2_string(/*wmem_allocator_t *scope, */const guint8 *ptr, gint length, const gunichar2 table[0x80]);


#endif
#ifndef __PROTO_H__
#define __PROTO_H__

#include "Base.h"
#include "tvbuff.h"
#include "ftypes.h"
/*
 * TODO:
 *
 * These could probably be used by existing code:
 *
 *  "IBM MS DBCS"
 *  JIS C 6226
 *
 * As those are added, change code such as the code in packet-bacapp.c
 * to use them.
 */

/*
 * For protocols (FT_PROTOCOL), aggregate items with subtrees (FT_NONE),
 * opaque byte-array fields (FT_BYTES), and other fields where there
 * is no choice of encoding (either because it's "just a bucket
 * of bytes" or because the encoding is completely fixed), we
 * have ENC_NA (for "Not Applicable").
 */
#define ENC_NA          0x00000000

#define ENC_BIG_ENDIAN      0x00000000
#define ENC_LITTLE_ENDIAN   0x80000000

#define ENC_ZIGBEE          0x40000000



/*
 * Historically, the only place the representation mattered for strings
 * was with FT_UINT_STRINGs, where we had FALSE for the string length
 * being big-endian and TRUE for it being little-endian.
 *
 * We now have encoding values for the character encoding.  The encoding
 * values are encoded in all but the top bit (which is the byte-order
 * bit, required for FT_UINT_STRING and for UCS-2 and UTF-16 strings)
 * and the bottom bit (which we ignore for now so that programs that
 * pass TRUE for the encoding just do ASCII).  (The encodings are given
 * directly as even numbers in hex, so that make-init-lua.pl can just
 * turn them into numbers for use in init.lua.)
 *
 * We don't yet process ASCII and UTF-8 differently.  Ultimately, for
 * ASCII, all bytes with the 8th bit set should be mapped to some "this
 * is not a valid character" code point, as ENC_ASCII should mean "this
 * is ASCII, not some extended variant thereof".  We should also map
 * 0x00 to that as well - null-terminated and null-padded strings
 * never have NULs in them, but counted strings might.  (Either that,
 * or the values for strings should be counted, not null-terminated.)
 * For UTF-8, invalid UTF-8 sequences should be mapped to the same
 * code point.
 *
 * For display, perhaps we should also map control characters to the
 * Unicode glyphs showing the name of the control character in small
 * caps, diagonally.  (Unfortunately, those only exist for C0, not C1.)
 *
 * *DO NOT* add anything to this set that is not a character encoding!
 */
#define ENC_CHARENCODING_MASK    0x3FFFFFFE  /* mask out byte-order bits and Zigbee bits */
#define ENC_ASCII                0x00000000
#define ENC_ISO_646_IRV          ENC_ASCII   /* ISO 646 International Reference Version = ASCII */
#define ENC_UTF_8                0x00000002
#define ENC_UTF_16               0x00000004
#define ENC_UCS_2                0x00000006
#define ENC_UCS_4                0x00000008
#define ENC_ISO_8859_1           0x0000000A
#define ENC_ISO_8859_2           0x0000000C
#define ENC_ISO_8859_3           0x0000000E
#define ENC_ISO_8859_4           0x00000010
#define ENC_ISO_8859_5           0x00000012
#define ENC_ISO_8859_6           0x00000014
#define ENC_ISO_8859_7           0x00000016
#define ENC_ISO_8859_8           0x00000018
#define ENC_ISO_8859_9           0x0000001A
#define ENC_ISO_8859_10          0x0000001C
#define ENC_ISO_8859_11          0x0000001E
/* #define ENC_ISO_8859_12          0x00000020 ISO 8859-12 was abandoned */
#define ENC_ISO_8859_13          0x00000022
#define ENC_ISO_8859_14          0x00000024
#define ENC_ISO_8859_15          0x00000026
#define ENC_ISO_8859_16          0x00000028
#define ENC_WINDOWS_1250         0x0000002A
#define ENC_3GPP_TS_23_038_7BITS 0x0000002C
#define ENC_EBCDIC               0x0000002E
#define ENC_MAC_ROMAN            0x00000030
#define ENC_CP437                0x00000032
#define ENC_ASCII_7BITS          0x00000034
#define ENC_T61                  0x00000036
#define ENC_EBCDIC_CP037         0x00000038
#define ENC_WINDOWS_1252         0x0000003A
#define ENC_WINDOWS_1251         0x0000003C
#define ENC_CP855                0x0000003E
#define ENC_CP866                0x00000040
#define ENC_ISO_646_BASIC        0x00000042
/*
 * Note that this enum values are parsed in make-init-lua.pl so make sure
 * any changes here still makes valid entries in init.lua.
 */
typedef enum {
/* Integral types */
    BASE_NONE    = 0,   /**< none */
    BASE_DEC     = 1,   /**< decimal */
    BASE_HEX     = 2,   /**< hexadecimal */
    BASE_OCT     = 3,   /**< octal */
    BASE_DEC_HEX = 4,   /**< decimal (hexadecimal) */
    BASE_HEX_DEC = 5,   /**< hexadecimal (decimal) */
    BASE_CUSTOM  = 6,   /**< call custom routine (in ->strings) to format */

/* Float types */
    BASE_FLOAT   = BASE_NONE, /**< decimal-format float */

/* String types */
    STR_ASCII    = 0,   /**< shows non-printable ASCII characters as C-style escapes */
    /* XXX, support for format_text_wsp() ? */
    STR_UNICODE  = 7,   /**< shows non-printable UNICODE characters as \\uXXXX (XXX for now non-printable characters display depends on UI) */

/* Byte separators */
    SEP_DOT      = 8,   /**< hexadecimal bytes with a period (.) between each byte */
    SEP_DASH     = 9,   /**< hexadecimal bytes with a dash (-) between each byte */
    SEP_COLON    = 10,  /**< hexadecimal bytes with a colon (:) between each byte */
    SEP_SPACE    = 11,  /**< hexadecimal bytes with a space between each byte */

/* Address types */
    BASE_NETMASK = 12,  /**< Used for IPv4 address that shouldn't be resolved (like for netmasks) */

/* Port types */
    BASE_PT_UDP  = 13,  /**< UDP port */
    BASE_PT_TCP  = 14,  /**< TCP port */
    BASE_PT_DCCP = 15,  /**< DCCP port */
    BASE_PT_SCTP = 16,  /**< SCTP port */

/* OUI types */
    BASE_OUI     = 17   /**< OUI resolution */

} field_display_e;


typedef enum {
	HF_REF_TYPE_NONE,       /**< Field is not referenced */
	HF_REF_TYPE_INDIRECT,   /**< Field is indirectly referenced (only applicable for FT_PROTOCOL) via. its child */
	HF_REF_TYPE_DIRECT      /**< Field is directly referenced */
} hf_ref_type;

//parse userdata
typedef struct
{
	guint  crumb_bit_offset;
	guint8 crumb_bit_length;
} crumb_spec_t;

/** information describing a header field */
//typedef struct _header_field_info header_field_info;
//struct _header_field_info {
//    /* ---------- set by dissector --------- */
//    const char        *name;              /**< [FIELDNAME] full name of this field */
//    const char        *abbrev;            /**< [FIELDABBREV] abbreviated name of this field */
//    enum ftenum        type;              /**< [FIELDTYPE] field type, one of FT_ (from ftypes.h) */
//    int                display;           /**< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
//    const void        *strings;           /**< [FIELDCONVERT] value_string, val64_string, range_string or true_false_string,
//                                               typically converted by VALS(), RVALS() or TFS().
//                                               If this is an FT_PROTOCOL or BASE_PROTOCOL_INFO then it points to the
//                                               associated protocol_t structure */
//    guint64            bitmask;           /**< [BITMASK] bitmask of interesting bits */
//    const char        *blurb;             /**< [FIELDDESCR] Brief description of field */
//
//    /* ------- set by proto routines (prefilled by HFILL macro, see below) ------ */
//    int                id;                /**< Field ID */
//    int                parent;            /**< parent protocol tree */
//    hf_ref_type        ref_type;          /**< is this field referenced by a filter */
//    int                same_name_prev_id; /**< ID of previous hfinfo with same abbrev */
//    header_field_info *same_name_next;    /**< Link to next hfinfo with same abbrev */
//};

//static inline guint64 get_uint64_value(proto_tree *tree, tvbuff_t *tvb, gint offset, guint length, const guint encoding);
 guint32 get_lte_uint32_field_value(tvbuff_t *tvb, gint offset, gint length, guint64 bitmask,const guint encoding);

 guint32 get_uint_value(tvbuff_t *tvb, gint offset, gint length, const guint encoding);
 guint32 proto_tree_set_uint(guint64 bitmask, guint32 value);

 guint64 get_lte_uint64_field_value(tvbuff_t *tvb, gint offset, gint length, guint64 bitmask,const guint encoding);
 inline guint64 get_uint64_value(tvbuff_t *tvb, gint offset, guint length, const guint encoding);

 int hfinfo_bitshift(guint64 bitmask);
 guint64 proto_tree_set_uint64(guint64 bitmask, guint64 value);

 /*static*/ /*inline const*/ guint8 *
	 get_string_value(/*wmem_allocator_t *scope,*/ tvbuff_t *tvb, gint start,
	 gint length, /*gint *ret_length,*/ const guint encoding);



//static guint64 proto_tree_set_uint64(guint64 bitmask, guint64 value);

//void _proto_tree_add_bits_ret_val(/*proto_tree *tree, const int hfindex,*/ tvbuff_t *tvb,  const guint bit_offset, const gint no_of_bits, guint64 *return_value/*, const guint encoding*/);
#endif /* proto.h */
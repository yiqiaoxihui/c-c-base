#include "StdAfx.h"
#include "strutil.h"

#define GN_CHAR_ALPHABET_SIZE 128


static gunichar IA5_default_alphabet[GN_CHAR_ALPHABET_SIZE] = {

	/*ITU-T recommendation T.50 specifies International Reference Alphabet 5 (IA5) */

	'?', '?', '?', '?', '?', '?', '?', '?',
	'?', '?', '?', '?', '?', '?', '?', '?',
	'?', '?', '?', '?', '?', '?', '?', '?',
	'?', '?', '?', '?', '?', '?', '?', '?',
	' ', '!', '\"','#', '$', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', ':', ';', '<', '=', '>', '?',
	'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
	'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
	'X',  'Y',  'Z',  '[',  '\\',  ']',  '^',  '_',
	'`', 'a',  'b',  'c',  'd',  'e',  'f',  'g',
	'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
	'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
	'x',  'y',  'z',  '{',  '|',  '}',  '~',  '?'
};

static gunichar
	char_def_ia5_alphabet_decode(unsigned char value)
{
	if (value < GN_CHAR_ALPHABET_SIZE) {
		return IA5_default_alphabet[value];
	}
	else {
		return '?';
	}
}

/* unicode_strchr */

/**
 * g_unichar_to_utf8:
 * @c: a Unicode character code
 * @outbuf: (out caller-allocates) (optional): output buffer, must have at
 *       least 6 bytes of space. If %NULL, the length will be computed and
 *       returned and nothing will be written to @outbuf.
 * 
 * Converts a single character to UTF-8.
 * 
 * Returns: number of bytes written
 */
//glib gutf8.c
int g_unichar_to_utf8 (gunichar c,
		   gchar   *outbuf)
{
  /* If this gets modified, also update the copy in g_string_insert_unichar() */
  guint len = 0;    
  int first;
  int i;

  if (c < 0x80)
    {
      first = 0;
      len = 1;
    }
  else if (c < 0x800)
    {
      first = 0xc0;
      len = 2;
    }
  else if (c < 0x10000)
    {
      first = 0xe0;
      len = 3;
    }
   else if (c < 0x200000)
    {
      first = 0xf0;
      len = 4;
    }
  else if (c < 0x4000000)
    {
      first = 0xf8;
      len = 5;
    }
  else
    {
      first = 0xfc;
      len = 6;
    }

  if (outbuf)
    {
      for (i = len - 1; i > 0; --i)
	{
	  outbuf[i] = (c & 0x3f) | 0x80;
	  c >>= 6;
	}
      outbuf[0] = c | first;
    }

  return len;
}

void IA5_7BIT_decode(/*unsigned*/ char * dest, const unsigned char* src, int len)
{
	int i, j;
	gunichar buf;

	for (i = 0, j = 0; j < len;  j++) {
		buf = char_def_ia5_alphabet_decode(src[j]);
		i += g_unichar_to_utf8(buf,&(dest[i]));
	}
	dest[i]=0;	//'\0'
}
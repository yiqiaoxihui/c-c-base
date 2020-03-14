#ifndef __STRUTIL_H__
#define __STRUTIL_H__

#include "Base.h"


int g_unichar_to_utf8 (gunichar c,gchar   *outbuf);
//void IA5_7BIT_decode(unsigned char * dest, const unsigned char* src, int len);

void IA5_7BIT_decode(/*unsigned*/ char * dest, const unsigned char* src, int len);

#endif
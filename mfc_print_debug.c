#include <conio.h>
#include <io.h>
#include <fcntl.h>
void inline print_error(std::string str)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),FOREGROUND_RED);
	_cprintf("Error:%s\n",str.c_str());
}
void inline print_warning(std::string str)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),FOREGROUND_INTENSITY|FOREGROUND_RED|FOREGROUND_GREEN);
	_cprintf("Warning:%s\n",str.c_str());
}
void inline print_normal(std::string str)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),7);
	_cprintf("INFO:%s\n",str.c_str());
}
void inline print_green(std::string str)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),FOREGROUND_GREEN);
	_cprintf("INFO:%s\n",str.c_str());
}

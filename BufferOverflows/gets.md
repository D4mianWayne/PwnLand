# `gets`

Ever had curiousity why `gets` is the vulnerable, I know most of the times people including me just search for the specific thing and instantly look for bottom line to see if something is vulnerable or not, if it is just get a way to exploit it, but I had this curiosity where I wanted to know what raelly gave away the `gets` and resulted in one of the functions which will become the target of the exploit developers and vulnerability research.

So, I knew that that the `gets` take the input until it encounters a newline character i.e. `\n`, looking at the source code of `iogets.c` in `/libio/` directory, the function was as follows, as defined `IO_gets`:-

```cpp
#include "libioP.h"
#include <limits.h>

char *
_IO_gets (char *buf)
{
  _IO_size_t count;
  int ch;
  char *retval;

  _IO_acquire_lock (_IO_stdin);
  ch = _IO_getc_unlocked (_IO_stdin);
  if (ch == EOF)
    {
      retval = NULL;
      goto unlock_return;
    }
  if (ch == '\n')
    count = 0;
  else
    {
      /* This is very tricky since a file descriptor may be in the
	 non-blocking mode. The error flag doesn't mean much in this
	 case. We return an error only when there is a new error. */
      int old_error = _IO_stdin->_IO_file_flags & _IO_ERR_SEEN;
      _IO_stdin->_IO_file_flags &= ~_IO_ERR_SEEN;
      buf[0] = (char) ch;
      count = _IO_getline (_IO_stdin, buf + 1, INT_MAX, '\n', 0) + 1;
      if (_IO_stdin->_IO_file_flags & _IO_ERR_SEEN)
	{
	  retval = NULL;
	  goto unlock_return;
	}
      else
	_IO_stdin->_IO_file_flags |= old_error;
    }
  buf[count] = 0;
  retval = buf;
unlock_return:
  _IO_release_lock (_IO_stdin);
  return retval;
}

weak_alias (_IO_gets, gets)  /* Make the function callable by the keyword `gets` */

link_warning (gets, "the `gets' function is dangerous and should not be used.") /* Warning for the use of `gets` in the program */
```

Let's break it down and see what exactly happens under the hood, so first of all as we know the argument expected to be of a `char` buf pointer where the input will be stored, then we have a local variable named `count` and the `ch` and the `retval`, moving on it does the I/O file operations to acquire the `stdin` lock then the `ch` chracter stores the data recieved by the `stdin` and perform two basic checks whether the `stdin` has already reached the `EOF` or a `\n` is encoutered and made the `count` value to 0 indicating recieved number of bytes. Now, moving on, it does the I/O operations on the `IO_FILE` structure by changing the flags of it and the neccessary values, then it made the `buf[0]` to of `ch`, then it takes the input via `_IO_getline` with the arguemnt being `stdin` `buf + 1`, `INT_MAX` which has a vlaue of `2147483647`, the maximun number of value a `signed int` can hold, followed by the newline character `\n` and  then 0 at the last. Then if successfully recieved input, change the neccessary informations about the `_IO_FILE` then NULL terminate the string recieved, then making the `retval` value to be same of the `buf` i.e. the string recieved call `unlock_return` this unlock the `stdin` and then return the `retval`.

So, this done, we see the function `_IO_getline` which was called within the `_IO_gets` function:-

```C
/* Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */

#include "libioP.h"
#include <string.h>

_IO_size_t
_IO_getline (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
	     int extract_delim)
{
  return _IO_getline_info (fp, buf, n, delim, extract_delim, (int *) 0);
}
libc_hidden_def (_IO_getline)

/* Algorithm based on that used by Berkeley pre-4.4 fgets implementation.

   Read chars into buf (of size n), until delim is seen.
   Return number of chars read (at most n).
   Does not put a terminating '\0' in buf.
   If extract_delim < 0, leave delimiter unread.
   If extract_delim > 0, insert delim in output. */

_IO_size_t
_IO_getline_info (_IO_FILE *fp, char *buf, _IO_size_t n, int delim,
		  int extract_delim, int *eof)
{
  char *ptr = buf;
  if (eof != NULL)
    *eof = 0;
  if (__builtin_expect (fp->_mode, -1) == 0)
    _IO_fwide (fp, -1);
  while (n != 0)
    {
      _IO_ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
	{
	  int c = __uflow (fp);
	  if (c == EOF)
	    {
	      if (eof)
		*eof = c;
	      break;
	    }
	  if (c == delim)
	    {
 	      if (extract_delim > 0)
		*ptr++ = c;
	      else if (extract_delim < 0)
		_IO_sputbackc (fp, c);
	      if (extract_delim > 0)
		++len;
	      return ptr - buf;
	    }
	  *ptr++ = c;
	  n--;
	}
      else
	{
	  char *t;
	  if ((_IO_size_t) len >= n)
	    len = n;
	  t = (char *) memchr ((void *) fp->_IO_read_ptr, delim, len);
	  if (t != NULL)
	    {
	      _IO_size_t old_len = ptr-buf;
	      len = t - fp->_IO_read_ptr;
	      if (extract_delim >= 0)
		{
		  ++t;
		  if (extract_delim > 0)
		    ++len;
		}
	      memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	      fp->_IO_read_ptr = t;
	      return old_len + len;
	    }
	  memcpy ((void *) ptr, (void *) fp->_IO_read_ptr, len);
	  fp->_IO_read_ptr += len;
	  ptr += len;
	  n -= len;
	}
    }
  return ptr - buf;
}
libc_hidden_def (_IO_getline_info)
```

Although the code might seems like a big bite to digest, to shorten it, this is the **Berkeley pre-4.4 fgets implementation** since it is a input taking algorithm, we don't really need to dwell in much all we should focus on the arguments, the catch which could've been a guesswork was the `_IO_getline` function was called:-

```C
_IO_getline (_IO_stdin, buf + 1, INT_MAX, '\n', 0) + 1;
```
If broke down, the size was not really defined and it's default value is `2147483647` and the terminating character defined here is the `\n`, hence the `gets` function, given any buffer pointer as argument will keep taking input until the size runs out which never really does, but usually we define buffer variable with the size less than the maximum size given here, this leads to the `gets` being a very dangerous function to use in real world.

### Keypoints

Take aways:-

* `gets` is defined in the `_IO_gets.c` in the `/libio/` of the GLIBC source.
* This was taken from the version 2.27 of GLIBC.
* `_IO_gets` calls the `_IO_getline`.
* `IO_gets` give  the default size of `2147483647` as default which is very large,
* Sincce `gets ` will keep taking input until a `\n` encounters or `2147483647` count reaches to 0(very less probabilty).
* As size is much larger, this makes this function a target for buffer overflow as we can overwrite the buffer more than the size defined.
#ifndef ZSCRIPT_ZSCRIPT_H
#define ZSCRIPT_ZSCRIPT_H

#include <vector>
#include <map>
#include "AST.h"
#include "CompilerUtils.h"
#include "Types.h"

#define MAX_SCRIPT_REGISTERS 1024

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#ifndef _REGEX_INTERNAL_H
#define _REGEX_INTERNAL_H 1

/* Definitions for data structures and routines for the regular
   expression library.
   Copyright (C) 1985,1989-93,1995-98,2000,2001,2002,2003,2005,2006,2008
   Free Software Foundation, Inc.
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
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301 USA.  */

#ifndef _REGEX_H
#define _REGEX_H 1

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

//#ifdef HAVE_SYS_TYPES_H
//#include <sys/types.h>
//#endif

#ifndef _LIBC
#define __USE_GNU	1
#endif

/* Allow the use in C++ code.  */
#ifdef __cplusplus
extern "C" {
#endif

/* The following two types have to be signed and unsigned integer type
   wide enough to hold a value of a pointer.  For most ANSI compilers
   ptrdiff_t and size_t should be likely OK.  Still size of these two
   types is 2 for Microsoft C.  Ugh... */
typedef long int s_reg_t;
typedef unsigned long int active_reg_t;

/* The following bits are used to determine the regexp syntax we
   recognize.  The set/not-set meanings are chosen so that Emacs syntax
   remains the value 0.  The bits are given in alphabetical order, and
   the definitions shifted by one from the previous bit; thus, when we
   add or remove a bit, only one other definition need change.  */
typedef unsigned long int reg_syntax_t;

#ifdef __USE_GNU
/* If this bit is not set, then \ inside a bracket expression is literal.
   If set, then such a \ quotes the following character.  */
# define RE_BACKSLASH_ESCAPE_IN_LISTS ((unsigned long int) 1)

/* If this bit is not set, then + and ? are operators, and \+ and \? are
     literals.
   If set, then \+ and \? are operators and + and ? are literals.  */
# define RE_BK_PLUS_QM (RE_BACKSLASH_ESCAPE_IN_LISTS << 1)

/* If this bit is set, then character classes are supported.  They are:
     [:alpha:], [:upper:], [:lower:],  [:digit:], [:alnum:], [:xdigit:],
     [:space:], [:print:], [:punct:], [:graph:], and [:cntrl:].
   If not set, then character classes are not supported.  */
# define RE_CHAR_CLASSES (RE_BK_PLUS_QM << 1)

/* If this bit is set, then ^ and $ are always anchors (outside bracket
     expressions, of course).
   If this bit is not set, then it depends:
        ^  is an anchor if it is at the beginning of a regular
           expression or after an open-group or an alternation operator;
        $  is an anchor if it is at the end of a regular expression, or
           before a close-group or an alternation operator.

   This bit could be (re)combined with RE_CONTEXT_INDEP_OPS, because
   POSIX draft 11.2 says that * etc. in leading positions is undefined.
   We already implemented a previous draft which made those constructs
   invalid, though, so we haven't changed the code back.  */
# define RE_CONTEXT_INDEP_ANCHORS (RE_CHAR_CLASSES << 1)

/* If this bit is set, then special characters are always special
     regardless of where they are in the pattern.
   If this bit is not set, then special characters are special only in
     some contexts; otherwise they are ordinary.  Specifically,
     * + ? and intervals are only special when not after the beginning,
     open-group, or alternation operator.  */
# define RE_CONTEXT_INDEP_OPS (RE_CONTEXT_INDEP_ANCHORS << 1)

/* If this bit is set, then *, +, ?, and { cannot be first in an re or
     immediately after an alternation or begin-group operator.  */
# define RE_CONTEXT_INVALID_OPS (RE_CONTEXT_INDEP_OPS << 1)

/* If this bit is set, then . matches newline.
   If not set, then it doesn't.  */
# define RE_DOT_NEWLINE (RE_CONTEXT_INVALID_OPS << 1)

/* If this bit is set, then . doesn't match NUL.
   If not set, then it does.  */
# define RE_DOT_NOT_NULL (RE_DOT_NEWLINE << 1)

/* If this bit is set, nonmatching lists [^...] do not match newline.
   If not set, they do.  */
# define RE_HAT_LISTS_NOT_NEWLINE (RE_DOT_NOT_NULL << 1)

/* If this bit is set, either \{...\} or {...} defines an
     interval, depending on RE_NO_BK_BRACES.
   If not set, \{, \}, {, and } are literals.  */
# define RE_INTERVALS (RE_HAT_LISTS_NOT_NEWLINE << 1)

/* If this bit is set, +, ? and | aren't recognized as operators.
   If not set, they are.  */
# define RE_LIMITED_OPS (RE_INTERVALS << 1)

/* If this bit is set, newline is an alternation operator.
   If not set, newline is literal.  */
# define RE_NEWLINE_ALT (RE_LIMITED_OPS << 1)

/* If this bit is set, then `{...}' defines an interval, and \{ and \}
     are literals.
  If not set, then `\{...\}' defines an interval.  */
# define RE_NO_BK_BRACES (RE_NEWLINE_ALT << 1)

/* If this bit is set, (...) defines a group, and \( and \) are literals.
   If not set, \(...\) defines a group, and ( and ) are literals.  */
# define RE_NO_BK_PARENS (RE_NO_BK_BRACES << 1)

/* If this bit is set, then \<digit> matches <digit>.
   If not set, then \<digit> is a back-reference.  */
# define RE_NO_BK_REFS (RE_NO_BK_PARENS << 1)

/* If this bit is set, then | is an alternation operator, and \| is literal.
   If not set, then \| is an alternation operator, and | is literal.  */
# define RE_NO_BK_VBAR (RE_NO_BK_REFS << 1)

/* If this bit is set, then an ending range point collating higher
     than the starting range point, as in [z-a], is invalid.
   If not set, then when ending range point collates higher than the
     starting range point, the range is ignored.  */
# define RE_NO_EMPTY_RANGES (RE_NO_BK_VBAR << 1)

/* If this bit is set, then an unmatched ) is ordinary.
   If not set, then an unmatched ) is invalid.  */
# define RE_UNMATCHED_RIGHT_PAREN_ORD (RE_NO_EMPTY_RANGES << 1)

/* If this bit is set, succeed as soon as we match the whole pattern,
   without further backtracking.  */
# define RE_NO_POSIX_BACKTRACKING (RE_UNMATCHED_RIGHT_PAREN_ORD << 1)

/* If this bit is set, do not process the GNU regex operators.
   If not set, then the GNU regex operators are recognized. */
# define RE_NO_GNU_OPS (RE_NO_POSIX_BACKTRACKING << 1)

/* If this bit is set, a syntactically invalid interval is treated as
   a string of ordinary characters.  For example, the ERE 'a{1' is
   treated as 'a\{1'.  */
# define RE_INVALID_INTERVAL_ORD (RE_NO_GNU_OPS << 1)

/* If this bit is set, then ignore case when matching.
   If not set, then case is significant.  */
# define RE_ICASE (RE_INVALID_INTERVAL_ORD << 1)

/* This bit is used internally like RE_CONTEXT_INDEP_ANCHORS but only
   for ^, because it is difficult to scan the regex backwards to find
   whether ^ should be special.  */
# define RE_CARET_ANCHORS_HERE (RE_ICASE << 1)

/* If this bit is set, then \{ cannot be first in an bre or
   immediately after an alternation or begin-group operator.  */
# define RE_CONTEXT_INVALID_DUP (RE_CARET_ANCHORS_HERE << 1)

/* If this bit is set, then no_sub will be set to 1 during
   re_compile_pattern.  */
#define RE_NO_SUB (RE_CONTEXT_INVALID_DUP << 1)
#endif

/* This global variable defines the particular regexp syntax to use (for
   some interfaces).  When a regexp is compiled, the syntax used is
   stored in the pattern buffer, so changing this does not affect
   already-compiled regexps.  */
extern reg_syntax_t re_syntax_options;

#ifdef __USE_GNU
/* Define combinations of the above bits for the standard possibilities.
   (The [[[ comments delimit what gets put into the Texinfo file, so
   don't delete them!)  */
/* [[[begin syntaxes]]] */
#define RE_SYNTAX_EMACS 0

#define RE_SYNTAX_AWK							\
  (RE_BACKSLASH_ESCAPE_IN_LISTS   | RE_DOT_NOT_NULL			\
   | RE_NO_BK_PARENS              | RE_NO_BK_REFS			\
   | RE_NO_BK_VBAR                | RE_NO_EMPTY_RANGES			\
   | RE_DOT_NEWLINE		  | RE_CONTEXT_INDEP_ANCHORS		\
   | RE_UNMATCHED_RIGHT_PAREN_ORD | RE_NO_GNU_OPS)

#define RE_SYNTAX_GNU_AWK						\
  ((RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS		\
   | RE_INVALID_INTERVAL_ORD)						\
   & ~(RE_DOT_NOT_NULL | RE_CONTEXT_INDEP_OPS				\
       | RE_CONTEXT_INVALID_OPS ))

#define RE_SYNTAX_POSIX_AWK						\
  (RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS		\
   | RE_INTERVALS	    | RE_NO_GNU_OPS				\
   | RE_INVALID_INTERVAL_ORD)

#define RE_SYNTAX_GREP							\
  (RE_BK_PLUS_QM              | RE_CHAR_CLASSES				\
   | RE_HAT_LISTS_NOT_NEWLINE | RE_INTERVALS				\
   | RE_NEWLINE_ALT)

#define RE_SYNTAX_EGREP							\
  (RE_CHAR_CLASSES        | RE_CONTEXT_INDEP_ANCHORS			\
   | RE_CONTEXT_INDEP_OPS | RE_HAT_LISTS_NOT_NEWLINE			\
   | RE_NEWLINE_ALT       | RE_NO_BK_PARENS				\
   | RE_NO_BK_VBAR)

#define RE_SYNTAX_POSIX_EGREP						\
  (RE_SYNTAX_EGREP | RE_INTERVALS | RE_NO_BK_BRACES			\
   | RE_INVALID_INTERVAL_ORD)

/* P1003.2/D11.2, section 4.20.7.1, lines 5078ff.  */
#define RE_SYNTAX_ED RE_SYNTAX_POSIX_BASIC

#define RE_SYNTAX_SED RE_SYNTAX_POSIX_BASIC

/* Syntax bits common to both basic and extended POSIX regex syntax.  */
#define _RE_SYNTAX_POSIX_COMMON						\
  (RE_CHAR_CLASSES | RE_DOT_NEWLINE      | RE_DOT_NOT_NULL		\
   | RE_INTERVALS  | RE_NO_EMPTY_RANGES)

#define RE_SYNTAX_POSIX_BASIC						\
  (_RE_SYNTAX_POSIX_COMMON | RE_BK_PLUS_QM | RE_CONTEXT_INVALID_DUP)

/* Differs from ..._POSIX_BASIC only in that RE_BK_PLUS_QM becomes
   RE_LIMITED_OPS, i.e., \? \+ \| are not recognized.  Actually, this
   isn't minimal, since other operators, such as \`, aren't disabled.  */
#define RE_SYNTAX_POSIX_MINIMAL_BASIC					\
  (_RE_SYNTAX_POSIX_COMMON | RE_LIMITED_OPS)

#define RE_SYNTAX_POSIX_EXTENDED					\
  (_RE_SYNTAX_POSIX_COMMON  | RE_CONTEXT_INDEP_ANCHORS			\
   | RE_CONTEXT_INDEP_OPS   | RE_NO_BK_BRACES				\
   | RE_NO_BK_PARENS        | RE_NO_BK_VBAR				\
   | RE_CONTEXT_INVALID_OPS | RE_UNMATCHED_RIGHT_PAREN_ORD)

/* Differs from ..._POSIX_EXTENDED in that RE_CONTEXT_INDEP_OPS is
   removed and RE_NO_BK_REFS is added.  */
#define RE_SYNTAX_POSIX_MINIMAL_EXTENDED				\
  (_RE_SYNTAX_POSIX_COMMON  | RE_CONTEXT_INDEP_ANCHORS			\
   | RE_CONTEXT_INVALID_OPS | RE_NO_BK_BRACES				\
   | RE_NO_BK_PARENS        | RE_NO_BK_REFS				\
   | RE_NO_BK_VBAR	    | RE_UNMATCHED_RIGHT_PAREN_ORD)
/* [[[end syntaxes]]] */

/* Maximum number of duplicates an interval can allow.  Some systems
   (erroneously) define this in other header files, but we want our
   value, so remove any previous define.  */
# ifdef RE_DUP_MAX
#  undef RE_DUP_MAX
# endif
/* If sizeof(int) == 2, then ((1 << 15) - 1) overflows.  */
# define RE_DUP_MAX (0x7fff)
#endif


/* POSIX `cflags' bits (i.e., information for `regcomp').  */

/* If this bit is set, then use extended regular expression syntax.
   If not set, then use basic regular expression syntax.  */
#define REG_EXTENDED 1

/* If this bit is set, then ignore case when matching.
   If not set, then case is significant.  */
#define REG_ICASE (REG_EXTENDED << 1)

/* If this bit is set, then anchors do not match at newline
     characters in the string.
   If not set, then anchors do match at newlines.  */
#define REG_NEWLINE (REG_ICASE << 1)

/* If this bit is set, then report only success or fail in regexec.
   If not set, then returns differ between not matching and errors.  */
#define REG_NOSUB (REG_NEWLINE << 1)


/* POSIX `eflags' bits (i.e., information for regexec).  */

/* If this bit is set, then the beginning-of-line operator doesn't match
     the beginning of the string (presumably because it's not the
     beginning of a line).
   If not set, then the beginning-of-line operator does match the
     beginning of the string.  */
#define REG_NOTBOL 1

/* Like REG_NOTBOL, except for the end-of-line.  */
#define REG_NOTEOL (1 << 1)

/* Use PMATCH[0] to delimit the start and end of the search in the
   buffer.  */
#define REG_STARTEND (1 << 2)


/* If any error codes are removed, changed, or added, update the
   `re_error_msg' table in regex.c.  */
typedef enum
{
#if defined _XOPEN_SOURCE || defined __USE_XOPEN2K
  REG_ENOSYS = -1,	/* This will never happen for this implementation.  */
#endif

  REG_NOERROR = 0,	/* Success.  */
  REG_NOMATCH,		/* Didn't find a match (for regexec).  */

  /* POSIX regcomp return error codes.  (In the order listed in the
     standard.)  */
  REG_BADPAT,		/* Invalid pattern.  */
  REG_ECOLLATE,		/* Inalid collating element.  */
  REG_ECTYPE,		/* Invalid character class name.  */
  REG_EESCAPE,		/* Trailing backslash.  */
  REG_ESUBREG,		/* Invalid back reference.  */
  REG_EBRACK,		/* Unmatched left bracket.  */
  REG_EPAREN,		/* Parenthesis imbalance.  */
  REG_EBRACE,		/* Unmatched \{.  */
  REG_BADBR,		/* Invalid contents of \{\}.  */
  REG_ERANGE,		/* Invalid range end.  */
  REG_ESPACE,		/* Ran out of memory.  */
  REG_BADRPT,		/* No preceding re for repetition op.  */

  /* Error codes we've added.  */
  REG_EEND,		/* Premature end.  */
  REG_ESIZE,		/* Compiled pattern bigger than 2^16 bytes.  */
  REG_ERPAREN		/* Unmatched ) or \); not returned from regcomp.  */
} reg_errcode_t;

/* This data structure represents a compiled pattern.  Before calling
   the pattern compiler, the fields `buffer', `allocated', `fastmap',
   `translate', and `no_sub' can be set.  After the pattern has been
   compiled, the `re_nsub' field is available.  All other fields are
   private to the regex routines.  */

#ifndef RE_TRANSLATE_TYPE
# define __RE_TRANSLATE_TYPE unsigned char *
# ifdef __USE_GNU
#  define RE_TRANSLATE_TYPE __RE_TRANSLATE_TYPE
# endif
#endif

#ifdef __USE_GNU
# define __REPB_PREFIX(name) name
#else
# define __REPB_PREFIX(name) __##name
#endif

struct re_pattern_buffer
{
  /* Space that holds the compiled pattern.  It is declared as
     `unsigned char *' because its elements are sometimes used as
     array indexes.  */
  unsigned char *__REPB_PREFIX(buffer);

  /* Number of bytes to which `buffer' points.  */
  unsigned long int __REPB_PREFIX(allocated);

  /* Number of bytes actually used in `buffer'.  */
  unsigned long int __REPB_PREFIX(used);

  /* Syntax setting with which the pattern was compiled.  */
  reg_syntax_t __REPB_PREFIX(syntax);

  /* Pointer to a fastmap, if any, otherwise zero.  re_search uses the
     fastmap, if there is one, to skip over impossible starting points
     for matches.  */
  char *__REPB_PREFIX(fastmap);

  /* Either a translate table to apply to all characters before
     comparing them, or zero for no translation.  The translation is
     applied to a pattern when it is compiled and to a string when it
     is matched.  */
  __RE_TRANSLATE_TYPE __REPB_PREFIX(translate);

  /* Number of subexpressions found by the compiler.  */
  size_t re_nsub;

  /* Zero if this pattern cannot match the empty string, one else.
     Well, in truth it's used only in `re_search_2', to see whether or
     not we should use the fastmap, so we don't set this absolutely
     perfectly; see `re_compile_fastmap' (the `duplicate' case).  */
  unsigned __REPB_PREFIX(can_be_null) : 1;

  /* If REGS_UNALLOCATED, allocate space in the `regs' structure
     for `max (RE_NREGS, re_nsub + 1)' groups.
     If REGS_REALLOCATE, reallocate space if necessary.
     If REGS_FIXED, use what's there.  */
#ifdef __USE_GNU
# define REGS_UNALLOCATED 0
# define REGS_REALLOCATE 1
# define REGS_FIXED 2
#endif
  unsigned __REPB_PREFIX(regs_allocated) : 2;

  /* Set to zero when `regex_compile' compiles a pattern; set to one
     by `re_compile_fastmap' if it updates the fastmap.  */
  unsigned __REPB_PREFIX(fastmap_accurate) : 1;

  /* If set, `re_match_2' does not return information about
     subexpressions.  */
  unsigned __REPB_PREFIX(no_sub) : 1;

  /* If set, a beginning-of-line anchor doesn't match at the beginning
     of the string.  */
  unsigned __REPB_PREFIX(not_bol) : 1;

  /* Similarly for an end-of-line anchor.  */
  unsigned __REPB_PREFIX(not_eol) : 1;

  /* If true, an anchor at a newline matches.  */
  unsigned __REPB_PREFIX(newline_anchor) : 1;
};

typedef struct re_pattern_buffer regex_t;

/* Type for byte offsets within the string.  POSIX mandates this.  */
typedef int regoff_t;


#ifdef __USE_GNU
/* This is the structure we store register match data in.  See
   regex.texinfo for a full description of what registers match.  */
struct re_registers
{
  unsigned num_regs;
  regoff_t *start;
  regoff_t *end;
};


/* If `regs_allocated' is REGS_UNALLOCATED in the pattern buffer,
   `re_match_2' returns information about at least this many registers
   the first time a `regs' structure is passed.  */
# ifndef RE_NREGS
#  define RE_NREGS 30
# endif
#endif


/* POSIX specification for registers.  Aside from the different names than
   `re_registers', POSIX uses an array of structures, instead of a
   structure of arrays.  */
typedef struct
{
  regoff_t rm_so;  /* Byte offset from string's start to substring's start.  */
  regoff_t rm_eo;  /* Byte offset from string's start to substring's end.  */
} regmatch_t;

/* Declarations for routines.  */

#ifdef __USE_GNU
/* Sets the current default syntax to SYNTAX, and return the old syntax.
   You can also simply assign to the `re_syntax_options' variable.  */
extern reg_syntax_t re_set_syntax (reg_syntax_t __syntax);

/* Compile the regular expression PATTERN, with length LENGTH
   and syntax given by the global `re_syntax_options', into the buffer
   BUFFER.  Return NULL if successful, and an error string if not.  */
extern const char *re_compile_pattern (const char *__pattern, size_t __length,
				       struct re_pattern_buffer *__buffer);


/* Compile a fastmap for the compiled pattern in BUFFER; used to
   accelerate searches.  Return 0 if successful and -2 if was an
   internal error.  */
extern int re_compile_fastmap (struct re_pattern_buffer *__buffer);


/* Search in the string STRING (with length LENGTH) for the pattern
   compiled into BUFFER.  Start searching at position START, for RANGE
   characters.  Return the starting position of the match, -1 for no
   match, or -2 for an internal error.  Also return register
   information in REGS (if REGS and BUFFER->no_sub are nonzero).  */
extern int re_search (struct re_pattern_buffer *__buffer, const char *__cstring,
		      int __length, int __start, int __range,
		      struct re_registers *__regs);


/* Like `re_search', but search in the concatenation of STRING1 and
   STRING2.  Also, stop searching at index START + STOP.  */
extern int re_search_2 (struct re_pattern_buffer *__buffer,
			const char *__string1, int __length1,
			const char *__string2, int __length2, int __start,
			int __range, struct re_registers *__regs, int __stop);


/* Like `re_search', but return how many characters in STRING the regexp
   in BUFFER matched, starting at position START.  */
extern int re_match (struct re_pattern_buffer *__buffer, const char *__cstring,
		     int __length, int __start, struct re_registers *__regs);


/* Relates to `re_match' as `re_search_2' relates to `re_search'.  */
extern int re_match_2 (struct re_pattern_buffer *__buffer,
		       const char *__string1, int __length1,
		       const char *__string2, int __length2, int __start,
		       struct re_registers *__regs, int __stop);


/* Set REGS to hold NUM_REGS registers, storing them in STARTS and
   ENDS.  Subsequent matches using BUFFER and REGS will use this memory
   for recording register information.  STARTS and ENDS must be
   allocated with malloc, and must each be at least `NUM_REGS * sizeof
   (regoff_t)' bytes long.

   If NUM_REGS == 0, then subsequent matches should allocate their own
   register data.

   Unless this function is called, the first search or match using
   PATTERN_BUFFER will allocate its own register data, without
   freeing the old data.  */
extern void re_set_registers (struct re_pattern_buffer *__buffer,
			      struct re_registers *__regs,
			      unsigned int __num_regs,
			      regoff_t *__starts, regoff_t *__ends);
#endif	/* Use GNU */

#if defined _REGEX_RE_COMP || (defined _LIBC && defined __USE_BSD)
# ifndef _CRAY
/* 4.2 bsd compatibility.  */
extern char *re_comp (const char *);
extern int re_exec (const char *);
# endif
#endif

/* GCC 2.95 and later have "__restrict"; C99 compilers have
   "restrict", and "configure" may have defined "restrict".  */
#ifndef __restrict
# if ! (2 < __GNUC__ || (2 == __GNUC__ && 95 <= __GNUC_MINOR__))
#  if defined restrict || 199901L <= __STDC_VERSION__
#   define __restrict restrict
#  else
#   define __restrict
#  endif
# endif
#endif
/* gcc 3.1 and up support the [restrict] syntax.  */
#ifndef __restrict_arr
# if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)) \
     && !defined __GNUG__
#  define __restrict_arr __restrict
# else
#  define __restrict_arr
# endif
#endif

/* POSIX compatibility.  */
extern int regcomp (regex_t *__restrict __preg,
		    const char *__restrict __pattern,
		    int __cflags);

extern int regexec (const regex_t *__restrict __preg,
		    const char *__restrict __cstring, size_t __nmatch,
		    regmatch_t __pmatch[__restrict_arr],
		    int __eflags);

extern size_t regerror (int __errcode, const regex_t *__restrict __preg,
			char *__restrict __errbuf, size_t __errbuf_size);

extern void regfree (regex_t *__preg);


#ifdef __cplusplus
}
#endif	/* C++ */

#endif /* regex.h */

#ifndef UNUSED
#	ifdef __GNUC__
#		define UNUSED __attribute__((unused))
#	else
#		define UNUSED
#	endif
#endif

#if defined HAVE_LANGINFO_H || defined HAVE_LANGINFO_CODESET || defined _LIBC
# include <langinfo.h>
#endif
#if defined HAVE_LOCALE_H || defined _LIBC
# include <locale.h>
#endif
#if defined HAVE_WCHAR_H || defined _LIBC
# include <wchar.h>
#endif /* HAVE_WCHAR_H || _LIBC */
#if defined HAVE_WCTYPE_H || defined _LIBC
# include <wctype.h>
#endif /* HAVE_WCTYPE_H || _LIBC */
#if defined HAVE_STDBOOL_H || defined _LIBC
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H || _LIBC */
#if !defined(ZOS_USS)
#if defined HAVE_STDINT_H || defined _LIBC
# include <stdint.h>
#endif /* HAVE_STDINT_H || _LIBC */
#endif /* !ZOS_USS */
#if defined _LIBC
# include <bits/libc-lock.h>
#else
# define __libc_lock_define(CLASS,NAME)
# define __libc_lock_init(NAME) do { } while (0)
# define __libc_lock_lock(NAME) do { } while (0)
# define __libc_lock_unlock(NAME) do { } while (0)
#endif

#ifndef GAWK
/* In case that the system doesn't have isblank().  */
#if !defined _LIBC && !defined HAVE_ISBLANK && !defined isblank
# define isblank(ch) ((ch) == ' ' || (ch) == '\t')
#endif
#else /* GAWK */
/*
 * This is a mess. On glibc systems you have to define
 * a magic constant to get isblank() out of <ctype.h>, since it's
 * a C99 function.  To heck with all that and borrow a page from
 * dfa.c's book.
 */

static int
is_blank (int c)
{
   return (c == ' ' || c == '\t');
}
#endif /* GAWK */

#ifdef _LIBC
# ifndef _RE_DEFINE_LOCALE_FUNCTIONS
#  define _RE_DEFINE_LOCALE_FUNCTIONS 1
#   include <locale/localeinfo.h>
#   include <locale/elem-hash.h>
#   include <locale/coll-lookup.h>
# endif
#endif

/* This is for other GNU distributions with internationalized messages.  */
#if (HAVE_LIBINTL_H && ENABLE_NLS) || defined _LIBC
# include <libintl.h>
# ifdef _LIBC
#  undef gettext
#  define gettext(msgid) \
  INTUSE(__dcgettext) (_libc_intl_domainname, msgid, LC_MESSAGES)
# endif
#else
# define gettext(msgid) (msgid)
#endif

#ifndef gettext_noop
/* This define is so xgettext can find the internationalizable
   strings.  */
# define gettext_noop(String) String
#endif

/* For loser systems without the definition.  */
#ifndef SIZE_MAX
# define SIZE_MAX ((size_t) -1)
#endif


#ifndef MB_CUR_MAX
#define MB_CUR_MAX 1
#endif

#if (defined MBS_SUPPORT) || _LIBC
# define RE_ENABLE_I18N
#endif

#if __GNUC__ >= 3
# define BE(expr, val) __builtin_expect (expr, val)
#else
# define BE(expr, val) (expr)
# ifdef inline
# undef inline
# endif
# define inline
#endif

/* Number of single byte character.  */
#define SBC_MAX 256

#define COLL_ELEM_LEN_MAX 8

/* The character which represents newline.  */
#define NEWLINE_CHAR '\n'
#define WIDE_NEWLINE_CHAR L'\n'

/* Rename to standard API for using out of glibc.  */
#ifndef _LIBC
# ifdef __wctype
# undef __wctype
# endif
# define __wctype wctype
# ifdef __iswctype
# undef __iswctype
# endif
# define __iswctype iswctype
# define __btowc btowc
# define __mbrtowc mbrtowc
#undef __mempcpy	/* GAWK */
# define __mempcpy mempcpy
# define __wcrtomb wcrtomb
# define __regfree regfree
# define attribute_hidden
#endif /* not _LIBC */

#ifdef __GNUC__
# define __attribute(arg) __attribute__ (arg)
#else
# define __attribute(arg)
#endif

extern const char __re_error_msgid[] attribute_hidden;
extern const size_t __re_error_msgid_idx[] attribute_hidden;

/* An integer used to represent a set of bits.  It must be unsigned,
   and must be at least as wide as unsigned int.  */
typedef unsigned long int bitset_word_t;
/* All bits set in a bitset_word_t.  */
#define BITSET_WORD_MAX ULONG_MAX
/* Number of bits in a bitset_word_t. Cast to int as most code use it
 * like that for counting */
#define BITSET_WORD_BITS ((int)(sizeof (bitset_word_t) * CHAR_BIT))
/* Number of bitset_word_t in a bit_set.  */
#define BITSET_WORDS (SBC_MAX / BITSET_WORD_BITS)
typedef bitset_word_t bitset_t[BITSET_WORDS];
typedef bitset_word_t *re_bitset_ptr_t;
typedef const bitset_word_t *re_const_bitset_ptr_t;

#define bitset_set(set,i) \
  (set[i / BITSET_WORD_BITS] |= (bitset_word_t) 1 << i % BITSET_WORD_BITS)
#define bitset_clear(set,i) \
  (set[i / BITSET_WORD_BITS] &= ~((bitset_word_t) 1 << i % BITSET_WORD_BITS))
#define bitset_contain(set,i) \
  (set[i / BITSET_WORD_BITS] & ((bitset_word_t) 1 << i % BITSET_WORD_BITS))
#define bitset_empty(set) memset (set, '\0', sizeof (bitset_t))
#define bitset_set_all(set) memset (set, '\xff', sizeof (bitset_t))
#define bitset_copy(dest,src) memcpy (dest, src, sizeof (bitset_t))

#define PREV_WORD_CONSTRAINT 0x0001
#define PREV_NOTWORD_CONSTRAINT 0x0002
#define NEXT_WORD_CONSTRAINT 0x0004
#define NEXT_NOTWORD_CONSTRAINT 0x0008
#define PREV_NEWLINE_CONSTRAINT 0x0010
#define NEXT_NEWLINE_CONSTRAINT 0x0020
#define PREV_BEGBUF_CONSTRAINT 0x0040
#define NEXT_ENDBUF_CONSTRAINT 0x0080
#define WORD_DELIM_CONSTRAINT 0x0100
#define NOT_WORD_DELIM_CONSTRAINT 0x0200

typedef enum
{
  INSIDE_WORD = PREV_WORD_CONSTRAINT | NEXT_WORD_CONSTRAINT,
  WORD_FIRST = PREV_NOTWORD_CONSTRAINT | NEXT_WORD_CONSTRAINT,
  WORD_LAST = PREV_WORD_CONSTRAINT | NEXT_NOTWORD_CONSTRAINT,
  INSIDE_NOTWORD = PREV_NOTWORD_CONSTRAINT | NEXT_NOTWORD_CONSTRAINT,
  LINE_FIRST = PREV_NEWLINE_CONSTRAINT,
  LINE_LAST = NEXT_NEWLINE_CONSTRAINT,
  BUF_FIRST = PREV_BEGBUF_CONSTRAINT,
  BUF_LAST = NEXT_ENDBUF_CONSTRAINT,
  WORD_DELIM = WORD_DELIM_CONSTRAINT,
  NOT_WORD_DELIM = NOT_WORD_DELIM_CONSTRAINT
} re_context_type;

typedef struct
{
  int alloc;
  int nelem;
  int *elems;
} re_node_set;

typedef enum
{
  NON_TYPE = 0,

  /* Node type, These are used by token, node, tree.  */
  CHARACTER = 1,
  END_OF_RE = 2,
  SIMPLE_BRACKET = 3,
  OP_BACK_REF = 4,
  OP_PERIOD = 5,
#ifdef RE_ENABLE_I18N
  COMPLEX_BRACKET = 6,
  OP_UTF8_PERIOD = 7,
#endif /* RE_ENABLE_I18N */

  /* We define EPSILON_BIT as a macro so that OP_OPEN_SUBEXP is used
     when the debugger shows values of this enum type.  */
#define EPSILON_BIT 8
  OP_OPEN_SUBEXP = EPSILON_BIT | 0,
  OP_CLOSE_SUBEXP = EPSILON_BIT | 1,
  OP_ALT = EPSILON_BIT | 2,
  OP_DUP_ASTERISK = EPSILON_BIT | 3,
  ANCHOR = EPSILON_BIT | 4,

  /* Tree type, these are used only by tree. */
  CONCAT = 16,
  SUBEXP = 17,

  /* Token type, these are used only by token.  */
  OP_DUP_PLUS = 18,
  OP_DUP_QUESTION,
  OP_OPEN_BRACKET,
  OP_CLOSE_BRACKET,
  OP_CHARSET_RANGE,
  OP_OPEN_DUP_NUM,
  OP_CLOSE_DUP_NUM,
  OP_NON_MATCH_LIST,
  OP_OPEN_COLL_ELEM,
  OP_CLOSE_COLL_ELEM,
  OP_OPEN_EQUIV_CLASS,
  OP_CLOSE_EQUIV_CLASS,
  OP_OPEN_CHAR_CLASS,
  OP_CLOSE_CHAR_CLASS,
  OP_WORD,
  OP_NOTWORD,
  OP_SPACE,
  OP_NOTSPACE,
  BACK_SLASH

} re_token_type_t;

#ifdef RE_ENABLE_I18N
typedef struct
{
  /* Multibyte characters.  */
  wchar_t *mbchars;

  /* Collating symbols.  */
# ifdef _LIBC
  int32_t *coll_syms;
# endif

  /* Equivalence classes. */
# ifdef _LIBC
  int32_t *equiv_classes;
# endif

  /* Range expressions. */
# ifdef _LIBC
  uint32_t *range_starts;
  uint32_t *range_ends;
# else /* not _LIBC */
  wchar_t *range_starts;
  wchar_t *range_ends;
# endif /* not _LIBC */

  /* Character classes. */
  wctype_t *char_classes;

  /* If this character set is the non-matching list.  */
  unsigned int non_match : 1;

  /* # of multibyte characters.  */
  int nmbchars;

  /* # of collating symbols.  */
  int ncoll_syms;

  /* # of equivalence classes. */
  int nequiv_classes;

  /* # of range expressions. */
  int nranges;

  /* # of character classes. */
  int nchar_classes;
} re_charset_t;
#endif /* RE_ENABLE_I18N */

typedef struct
{
  union
  {
    unsigned char c;		/* for CHARACTER */
    re_bitset_ptr_t sbcset;	/* for SIMPLE_BRACKET */
#ifdef RE_ENABLE_I18N
    re_charset_t *mbcset;	/* for COMPLEX_BRACKET */
#endif /* RE_ENABLE_I18N */
    int idx;			/* for BACK_REF */
    re_context_type ctx_type;	/* for ANCHOR */
  } opr;
#if __GNUC__ >= 2
  re_token_type_t type : 8;
#else
  re_token_type_t type;
#endif
  unsigned int constraint : 10;	/* context constraint */
  unsigned int duplicated : 1;
  unsigned int opt_subexp : 1;
#ifdef RE_ENABLE_I18N
  unsigned int accept_mb : 1;
  /* These 2 bits can be moved into the union if needed (e.g. if running out
     of bits; move opr.c to opr.c.c and move the flags to opr.c.flags).  */
  unsigned int mb_partial : 1;
#endif
  unsigned int word_char : 1;
} re_token_t;

#define IS_EPSILON_NODE(type) ((type) & EPSILON_BIT)

struct re_string_t
{
  /* Indicate the raw buffer which is the original string passed as an
     argument of regexec(), re_search(), etc..  */
  const unsigned char *raw_mbs;
  /* Store the multibyte string.  In case of "case insensitive mode" like
     REG_ICASE, upper cases of the string are stored, otherwise MBS points
     the same address that RAW_MBS points.  */
  unsigned char *mbs;
#ifdef RE_ENABLE_I18N
  /* Store the wide character string which is corresponding to MBS.  */
  wint_t *wcs;
  int *offsets;
  mbstate_t cur_state;
#endif
  /* Index in RAW_MBS.  Each character mbs[i] corresponds to
     raw_mbs[raw_mbs_idx + i].  */
  int raw_mbs_idx;
  /* The length of the valid characters in the buffers.  */
  int valid_len;
  /* The corresponding number of bytes in raw_mbs array.  */
  int valid_raw_len;
  /* The length of the buffers MBS and WCS.  */
  int bufs_len;
  /* The index in MBS, which is updated by re_string_fetch_byte.  */
  int cur_idx;
  /* length of RAW_MBS array.  */
  int raw_len;
  /* This is RAW_LEN - RAW_MBS_IDX + VALID_LEN - VALID_RAW_LEN.  */
  int len;
  /* End of the buffer may be shorter than its length in the cases such
     as re_match_2, re_search_2.  Then, we use STOP for end of the buffer
     instead of LEN.  */
  int raw_stop;
  /* This is RAW_STOP - RAW_MBS_IDX adjusted through OFFSETS.  */
  int stop;

  /* The context of mbs[0].  We store the context independently, since
     the context of mbs[0] may be different from raw_mbs[0], which is
     the beginning of the input string.  */
  unsigned int tip_context;
  /* The translation passed as a part of an argument of re_compile_pattern.  */
  RE_TRANSLATE_TYPE trans;
  /* Copy of re_dfa_t's word_char.  */
  re_const_bitset_ptr_t word_char;
  /* 1 if REG_ICASE.  */
  unsigned char icase;
  unsigned char is_utf8;
  unsigned char map_notascii;
  unsigned char mbs_allocated;
  unsigned char offsets_needed;
  unsigned char newline_anchor;
  unsigned char word_ops_used;
  int mb_cur_max;
};
typedef struct re_string_t re_string_t;


struct re_dfa_t;
typedef struct re_dfa_t re_dfa_t;

#ifndef _LIBC
# ifdef __i386__
#  define internal_function   __attribute ((regparm (3), stdcall))
# else
#  define internal_function
# endif
#endif

#ifndef NOT_IN_libc
static reg_errcode_t re_string_realloc_buffers (re_string_t *pstr,
						int new_buf_len)
     internal_function;
# ifdef RE_ENABLE_I18N
static void build_wcs_buffer (re_string_t *pstr) internal_function;
static reg_errcode_t build_wcs_upper_buffer (re_string_t *pstr)
  internal_function;
# endif /* RE_ENABLE_I18N */
static void build_upper_buffer (re_string_t *pstr) internal_function;
static void re_string_translate_buffer (re_string_t *pstr) internal_function;
static unsigned int re_string_context_at (const re_string_t *input, int idx,
					  int eflags)
     internal_function __attribute ((pure));
#endif
#define re_string_peek_byte(pstr, offset) \
  ((pstr)->mbs[(pstr)->cur_idx + offset])
#define re_string_fetch_byte(pstr) \
  ((pstr)->mbs[(pstr)->cur_idx++])
#define re_string_first_byte(pstr, idx) \
  ((idx) == (pstr)->valid_len || (pstr)->wcs[idx] != WEOF)
#define re_string_is_single_byte_char(pstr, idx) \
  ((pstr)->wcs[idx] != WEOF && ((pstr)->valid_len == (idx) + 1 \
				|| (pstr)->wcs[(idx) + 1] != WEOF))
#define re_string_eoi(pstr) ((pstr)->stop <= (pstr)->cur_idx)
#define re_string_cur_idx(pstr) ((pstr)->cur_idx)
#define re_string_get_buffer(pstr) ((pstr)->mbs)
#define re_string_length(pstr) ((pstr)->len)
#define re_string_byte_at(pstr,idx) ((pstr)->mbs[idx])
#define re_string_skip_bytes(pstr,idx) ((pstr)->cur_idx += (idx))
#define re_string_set_index(pstr,idx) ((pstr)->cur_idx = (idx))

#ifndef _LIBC
# if HAVE_ALLOCA
#  if (_MSC_VER)
#   include <malloc.h>
#   define __libc_use_alloca(n) 0
#  else
#   include <alloca.h>
/* The OS usually guarantees only one guard page at the bottom of the stack,
   and a page size can be as small as 4096 bytes.  So we cannot safely
   allocate anything larger than 4096 bytes.  Also care for the possibility
   of a few compiler-allocated temporary stack slots.  */
#  define __libc_use_alloca(n) ((n) < 4032)
#  endif
# else
/* alloca is implemented with malloc, so just use malloc.  */
#  define __libc_use_alloca(n) 0
# endif
#endif

#define re_malloc(t,n) ((t *) malloc ((n) * sizeof (t)))
/* SunOS 4.1.x realloc doesn't accept null pointers: pre-Standard C. Sigh. */
#define re_realloc(p,t,n) ((p != NULL) ? (t *) realloc (p,(n)*sizeof(t)) : (t *) calloc(n,sizeof(t)))
#define re_free(p) free (p)

struct bin_tree_t
{
  struct bin_tree_t *parent;
  struct bin_tree_t *left;
  struct bin_tree_t *right;
  struct bin_tree_t *first;
  struct bin_tree_t *next;

  re_token_t token;

  /* `node_idx' is the index in dfa->nodes, if `type' == 0.
     Otherwise `type' indicate the type of this node.  */
  int node_idx;
};
typedef struct bin_tree_t bin_tree_t;

#define BIN_TREE_STORAGE_SIZE \
  ((1024 - sizeof (void *)) / sizeof (bin_tree_t))

struct bin_tree_storage_t
{
  struct bin_tree_storage_t *next;
  bin_tree_t data[BIN_TREE_STORAGE_SIZE];
};
typedef struct bin_tree_storage_t bin_tree_storage_t;

#define CONTEXT_WORD 1
#define CONTEXT_NEWLINE (CONTEXT_WORD << 1)
#define CONTEXT_BEGBUF (CONTEXT_NEWLINE << 1)
#define CONTEXT_ENDBUF (CONTEXT_BEGBUF << 1)

#define IS_WORD_CONTEXT(c) ((c) & CONTEXT_WORD)
#define IS_NEWLINE_CONTEXT(c) ((c) & CONTEXT_NEWLINE)
#define IS_BEGBUF_CONTEXT(c) ((c) & CONTEXT_BEGBUF)
#define IS_ENDBUF_CONTEXT(c) ((c) & CONTEXT_ENDBUF)
#define IS_ORDINARY_CONTEXT(c) ((c) == 0)

#define IS_WORD_CHAR(ch) (isalnum (ch) || (ch) == '_')
#define IS_NEWLINE(ch) ((ch) == NEWLINE_CHAR)
#define IS_WIDE_WORD_CHAR(ch) (iswalnum (ch) || (ch) == L'_')
#define IS_WIDE_NEWLINE(ch) ((ch) == WIDE_NEWLINE_CHAR)

#define NOT_SATISFY_PREV_CONSTRAINT(constraint,context) \
 ((((constraint) & PREV_WORD_CONSTRAINT) && !IS_WORD_CONTEXT (context)) \
  || ((constraint & PREV_NOTWORD_CONSTRAINT) && IS_WORD_CONTEXT (context)) \
  || ((constraint & PREV_NEWLINE_CONSTRAINT) && !IS_NEWLINE_CONTEXT (context))\
  || ((constraint & PREV_BEGBUF_CONSTRAINT) && !IS_BEGBUF_CONTEXT (context)))

#define NOT_SATISFY_NEXT_CONSTRAINT(constraint,context) \
 ((((constraint) & NEXT_WORD_CONSTRAINT) && !IS_WORD_CONTEXT (context)) \
  || (((constraint) & NEXT_NOTWORD_CONSTRAINT) && IS_WORD_CONTEXT (context)) \
  || (((constraint) & NEXT_NEWLINE_CONSTRAINT) && !IS_NEWLINE_CONTEXT (context)) \
  || (((constraint) & NEXT_ENDBUF_CONSTRAINT) && !IS_ENDBUF_CONTEXT (context)))

struct re_dfastate_t
{
  unsigned int hash;
  re_node_set nodes;
  re_node_set non_eps_nodes;
  re_node_set inveclosure;
  re_node_set *entrance_nodes;
  struct re_dfastate_t **trtable, **word_trtable;
  unsigned int context : 4;
  unsigned int halt : 1;
  /* If this state can accept `multi byte'.
     Note that we refer to multibyte characters, and multi character
     collating elements as `multi byte'.  */
  unsigned int accept_mb : 1;
  /* If this state has backreference node(s).  */
  unsigned int has_backref : 1;
  unsigned int has_constraint : 1;
};
typedef struct re_dfastate_t re_dfastate_t;

struct re_state_table_entry
{
  int num;
  int alloc;
  re_dfastate_t **array;
};

/* Array type used in re_sub_match_last_t and re_sub_match_top_t.  */

typedef struct
{
  int next_idx;
  int alloc;
  re_dfastate_t **array;
} state_array_t;

/* Store information about the node NODE whose type is OP_CLOSE_SUBEXP.  */

typedef struct
{
  int node;
  int str_idx; /* The position NODE match at.  */
  state_array_t path;
} re_sub_match_last_t;

/* Store information about the node NODE whose type is OP_OPEN_SUBEXP.
   And information about the node, whose type is OP_CLOSE_SUBEXP,
   corresponding to NODE is stored in LASTS.  */

typedef struct
{
  int str_idx;
  int node;
  state_array_t *path;
  int alasts; /* Allocation size of LASTS.  */
  int nlasts; /* The number of LASTS.  */
  re_sub_match_last_t **lasts;
} re_sub_match_top_t;

struct re_backref_cache_entry
{
  int node;
  int str_idx;
  int subexp_from;
  int subexp_to;
  char more;
  char unused;
  unsigned short int eps_reachable_subexps_map;
};

typedef struct
{
  /* The string object corresponding to the input string.  */
  re_string_t input;
#if defined _LIBC || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L)
  const re_dfa_t *const dfa;
#else
  const re_dfa_t *dfa;
#endif
  /* EFLAGS of the argument of regexec.  */
  int eflags;
  /* Where the matching ends.  */
  int match_last;
  int last_node;
  /* The state log used by the matcher.  */
  re_dfastate_t **state_log;
  int state_log_top;
  /* Back reference cache.  */
  int nbkref_ents;
  int abkref_ents;
  struct re_backref_cache_entry *bkref_ents;
  int max_mb_elem_len;
  int nsub_tops;
  int asub_tops;
  re_sub_match_top_t **sub_tops;
} re_match_context_t;

typedef struct
{
  re_dfastate_t **sifted_states;
  re_dfastate_t **limited_states;
  int last_node;
  int last_str_idx;
  re_node_set limits;
} re_sift_context_t;

struct re_fail_stack_ent_t
{
  int idx;
  int node;
  regmatch_t *regs;
  re_node_set eps_via_nodes;
};

struct re_fail_stack_t
{
  int num;
  int alloc;
  struct re_fail_stack_ent_t *stack;
};

struct re_dfa_t
{
  re_token_t *nodes;
  size_t nodes_alloc;
  size_t nodes_len;
  int *nexts;
  int *org_indices;
  re_node_set *edests;
  re_node_set *eclosures;
  re_node_set *inveclosures;
  struct re_state_table_entry *state_table;
  re_dfastate_t *init_state;
  re_dfastate_t *init_state_word;
  re_dfastate_t *init_state_nl;
  re_dfastate_t *init_state_begbuf;
  bin_tree_t *str_tree;
  bin_tree_storage_t *str_tree_storage;
  re_bitset_ptr_t sb_char;
  int str_tree_storage_idx;

  /* number of subexpressions `re_nsub' is in regex_t.  */
  unsigned int state_hash_mask;
  int init_node;
  int nbackref; /* The number of backreference in this dfa.  */

  /* Bitmap expressing which backreference is used.  */
  bitset_word_t used_bkref_map;
  bitset_word_t completed_bkref_map;

  unsigned int has_plural_match : 1;
  /* If this dfa has "multibyte node", which is a backreference or
     a node which can accept multibyte character or multi character
     collating element.  */
  unsigned int has_mb_node : 1;
  unsigned int is_utf8 : 1;
  unsigned int map_notascii : 1;
  unsigned int word_ops_used : 1;
  int mb_cur_max;
  bitset_t word_char;
  reg_syntax_t syntax;
  int *subexp_map;
#ifdef DEBUG
  char* re_str;
#endif
#if defined _LIBC
  __libc_lock_define (, lock)
#endif
};

#define re_node_set_init_empty(set) memset (set, '\0', sizeof (re_node_set))
#define re_node_set_remove(set,id) \
  (re_node_set_remove_at (set, re_node_set_contains (set, id) - 1))
#define re_node_set_empty(p) ((p)->nelem = 0)
#define re_node_set_free(set) re_free ((set)->elems)


typedef enum
{
  SB_CHAR,
  MB_CHAR,
  EQUIV_CLASS,
  COLL_SYM,
  CHAR_CLASS
} bracket_elem_type;

typedef struct
{
  bracket_elem_type type;
  union
  {
    unsigned char ch;
    unsigned char *name;
    wchar_t wch;
  } opr;
} bracket_elem_t;


/* Inline functions for bitset operation.  */
static inline void
bitset_not (bitset_t set)
{
  int bitset_i;
  for (bitset_i = 0; bitset_i < BITSET_WORDS; ++bitset_i)
    set[bitset_i] = ~set[bitset_i];
}

static inline void
bitset_merge (bitset_t dest, const bitset_t src)
{
  int bitset_i;
  for (bitset_i = 0; bitset_i < BITSET_WORDS; ++bitset_i)
    dest[bitset_i] |= src[bitset_i];
}

static inline void
bitset_mask (bitset_t dest, const bitset_t src)
{
  int bitset_i;
  for (bitset_i = 0; bitset_i < BITSET_WORDS; ++bitset_i)
    dest[bitset_i] &= src[bitset_i];
}

#ifdef RE_ENABLE_I18N
/* Inline functions for re_string.  */
static inline int
internal_function __attribute ((pure))
re_string_char_size_at (const re_string_t *pstr, int idx)
{
  int byte_idx;
  if (pstr->mb_cur_max == 1)
    return 1;
  for (byte_idx = 1; idx + byte_idx < pstr->valid_len; ++byte_idx)
    if (pstr->wcs[idx + byte_idx] != WEOF)
      break;
  return byte_idx;
}

static inline wint_t
internal_function __attribute ((pure))
re_string_wchar_at (const re_string_t *pstr, int idx)
{
  if (pstr->mb_cur_max == 1)
    return (wint_t) pstr->mbs[idx];
  return (wint_t) pstr->wcs[idx];
}

# ifndef NOT_IN_libc
static int
internal_function __attribute ((pure))
re_string_elem_size_at (const re_string_t *pstr, int idx)
{
#  ifdef _LIBC
  const unsigned char *p, *extra;
  const int32_t *table, *indirect;
  int32_t tmp;
#   include <locale/weight.h>
  uint_fast32_t nrules = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);

  if (nrules != 0)
    {
      table = (const int32_t *) _NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEMB);
      extra = (const unsigned char *)
	_NL_CURRENT (LC_COLLATE, _NL_COLLATE_EXTRAMB);
      indirect = (const int32_t *) _NL_CURRENT (LC_COLLATE,
						_NL_COLLATE_INDIRECTMB);
      p = pstr->mbs + idx;
      tmp = findidx (&p);
      return p - pstr->mbs - idx;
    }
  else
#  endif /* _LIBC */
    return 1;
}
# endif
#endif /* RE_ENABLE_I18N */

#endif /*  _REGEX_INTERNAL_H */

namespace ZScript
{
	class CompileErrorHandler;

	class TypeStore;
	class Program;
	class Script;
	class Variable;
	class BuiltinVariable;
	class Function;
	class Scope;
	class RootScope;
	class ScriptScope;
	class FunctionScope;
	
	////////////////////////////////////////////////////////////////
	// Program
	
	class Program : private NoCopy
	{
	public:
		Program(ASTFile&, CompileErrorHandler*);
		~Program();

		ASTFile& getRoot() {return root_;}
		TypeStore const& getTypeStore() const {return typeStore_;}
		TypeStore& getTypeStore() {return typeStore_;}
		RootScope& getScope() const {return *rootScope_;}

		std::vector<Script*> scripts;
		Script* getScript(std::string const& name) const;
		Script* getScript(ASTScript* node) const;
		Script* addScript(ASTScript&, Scope&, CompileErrorHandler*);

		// Gets the non-internal (user-defined) global scope functions.
		std::vector<Function*> getUserGlobalFunctions() const;

		// Gets all user-defined functions.
		std::vector<Function*> getUserFunctions() const;

		// Return a list of all errors in the script declaration.
		std::vector<CompileError const*> getErrors() const;
		// Does this script have a declaration error?
		bool hasError() const {return (getErrors().size());}

	private:
		std::map<std::string, Script*> scriptsByName_;
		std::map<ASTScript*, Script*> scriptsByNode_;

		TypeStore typeStore_;
		RootScope* rootScope_;
		ASTFile& root_;
	};

	// Gets all defined functions.
	std::vector<Function*> getFunctions(Program const&);

	////////////////////////////////////////////////////////////////
	// Script

	class UserScript;
	class BuiltinScript;
	
	class Script
	{
	public:
		virtual ~Script();

		virtual ScriptType getType() const = 0;
		virtual std::string const& getName() const = 0;
		virtual ASTScript* getNode() const = 0;
		virtual ScriptScope& getScope() = 0;
		virtual ScriptScope const& getScope() const = 0;

		std::vector<Opcode*> code;

	protected:
		Script(Program& program);

	private:
		Program& program;
	};

	class UserScript : public Script
	{
		friend UserScript* createScript(
				Program&, Scope&, ASTScript&, CompileErrorHandler*);

	public:
		ScriptType getType() const /*override*/;
		std::string const& getName() const /*override*/ {return node.name;};
		ASTScript* getNode() const /*override*/ {return &node;};
		ScriptScope& getScope() /*override*/ {return *scope;}
		ScriptScope const& getScope() const /*override*/ {return *scope;}

	private:
		UserScript(Program&, ASTScript&);

		ASTScript& node;
		ScriptScope* scope;
	};

	class BuiltinScript : public Script
	{
		friend BuiltinScript* createScript(
				Program&, Scope&, ScriptType, std::string const& name,
				CompileErrorHandler*);

	public:
		ScriptType getType() const /*override*/ {return type;}
		std::string const& getName() const /*override*/ {return name;};
		ASTScript* getNode() const /*override*/ {return NULL;};
		ScriptScope& getScope() /*override*/ {return *scope;}
		ScriptScope const& getScope() const /*override*/ {return *scope;}
		
	private:
		BuiltinScript(Program&, ScriptType, std::string const& name);
		
		ScriptType type;
		std::string name;
		ScriptScope* scope;
	};

	UserScript* createScript(
			Program&, Scope&, ASTScript&, CompileErrorHandler* = NULL);
	BuiltinScript* createScript(
			Program&, Scope&, ScriptType, std::string const& name,
			CompileErrorHandler* = NULL);
	
	Function* getRunFunction(Script const&);
	optional<int> getLabel(Script const&);

	////////////////////////////////////////////////////////////////
	// Datum
	
	// Something that can be resolved to a data value.
	class Datum
	{
	public:
		// The containing scope.
		Scope& scope;

		// The type of this data.
		DataType const& type;

		// Id for lookup tables.
		int const id;

		// Get the data's name.
		virtual optional<std::string> getName() const {return nullopt;}
		
		// Get the value at compile time.
		virtual optional<long> getCompileTimeValue() const {return nullopt;}

		// Get the declaring node.
		virtual AST* getNode() const {return NULL;}
		
		// Get the global register this uses.
		virtual optional<int> getGlobalId() const {return nullopt;}
		
	protected:
		Datum(Scope& scope, DataType const& type);

		// Call in static creation function to register with scope.
		bool tryAddToScope(CompileErrorHandler* = NULL);
	};

	// Is this datum a global value?
	bool isGlobal(Datum const& data);

	// Return the stack offset of the value.
	optional<int> getStackOffset(Datum const&);

	// A literal value that requires memory management.
	class Literal : public Datum
	{
	public:
		static Literal* create(
				Scope&, ASTLiteral&, DataType const&,
				CompileErrorHandler* = NULL);
		
		ASTLiteral* getNode() const {return &node;}

	private:
		Literal(Scope& scope, ASTLiteral& node, DataType const& type);

		ASTLiteral& node;
	};

	// A variable.
	class Variable : public Datum
	{
	public:
		static Variable* create(
				Scope&, ASTDataDecl&, DataType const&,
				CompileErrorHandler* = NULL);

		optional<std::string> getName() const {return node.name;}
		ASTDataDecl* getNode() const {return &node;}
		optional<int> getGlobalId() const {return globalId;}

	private:
		Variable(Scope& scope, ASTDataDecl& node, DataType const& type);

		ASTDataDecl& node;
		optional<int> globalId;
	};

	// A compiler generated variable.
	class BuiltinVariable : public Datum
	{
	public:
		static BuiltinVariable* create(
				Scope&, DataType const&, std::string const& name,
				CompileErrorHandler* = NULL);

		optional<std::string> getName() const {return name;}
		optional<int> getGlobalId() const {return globalId;}

	private:
		BuiltinVariable(Scope&, DataType const&, std::string const& name);

		std::string const name;
		optional<int> globalId;
	};

	// An inlined constant.
	class Constant : public Datum
	{
	public:
		static Constant* create(
				Scope&, ASTDataDecl&, DataType const&, long value,
				CompileErrorHandler* = NULL);

		optional<std::string> getName() const;

		optional<long> getCompileTimeValue() const {return value;}

		ASTDataDecl* getNode() const {return &node;}
	
	private:
		Constant(Scope&, ASTDataDecl&, DataType const&, long value);

		ASTDataDecl& node;
		long value;
	};

	// A builtin data value.
	class BuiltinConstant : public Datum
	{
	public:
		static BuiltinConstant* create(
				Scope&, DataType const&, std::string const& name, long value,
				CompileErrorHandler* = NULL);

		optional<std::string> getName() const {return name;}
		optional<long> getCompileTimeValue() const {return value;}

	private:
		BuiltinConstant(Scope&, DataType const&,
		                std::string const& name, long value);

		std::string name;
		long value;
	};

	////////////////////////////////////////////////////////////////
	// FunctionSignature

	// Comparable signature structure.
	class FunctionSignature
	{
	public:
		FunctionSignature(
				std::string const& name,
				std::vector<DataType const*> const& parameterTypes);
		FunctionSignature(Function const& function);

		int compare(FunctionSignature const& other) const;
		bool operator==(FunctionSignature const& other) const;
		bool operator<(FunctionSignature const& other) const;
		std::string asString() const;
		operator std::string() const {return asString();}

		std::string name;
		std::vector<DataType const*> parameterTypes;
	};
	
	
	////////////////////////////////////////////////////////////////
	// Function
	
	class Function
	{
	public:
		
		Function(DataType const* returnType, std::string const& name,
		         std::vector<DataType const*> paramTypes, int id);
		~Function();
		
		DataType const* returnType;
		std::string name;
		std::vector<DataType const*> paramTypes;
		int id;

		ASTFuncDecl* node;
		FunctionScope* internalScope;
		BuiltinVariable* thisVar;

		// Get the opcodes.
		std::vector<Opcode*> const& getCode() const {return ownedCode;}
		// Get and remove the code for this function.
		std::vector<Opcode*> takeCode();
		// Add code for this function, transferring ownership.
		// Clears the input vector.
		void giveCode(std::vector<Opcode*>& code);
		
		FunctionSignature getSignature() const {
			return FunctionSignature(*this);}
		
		// If this is a script level function, return that script.
		Script* getScript() const;

		int getLabel() const;

		// If this is a tracing function (enabled by #option trace)
		bool isTracing() const;
		
	private:
		mutable optional<int> label;

		// Code implementing this function.
		std::vector<Opcode*> ownedCode;
	};

	// Is this function a "run" function?
	bool isRun(Function const&);

	// Get the size of the function stack.
	int getStackSize(Function const&);

	// Get the function's parameter count, including "this" if present.
	int getParameterCount(Function const&);
}

#endif


#ifndef ECPP_REGEX_H
#define ECPP_REGEX_H

//#include <sys/types.h>
//#include <stdlib.h>
//#include <regex.h>
#include <vector>
#include <string>

namespace POSIX
{

struct Group
{
    int start;
    int end;
};

class Match
{
    private:
        std::string match;
        std::vector<Group> pgroups;

        void addGroup(int start, int end);

    public:
        Match();
        Match(std::string match);

        /*
            Returns the starting index of the group
        */
        int start(unsigned int group);

        /*
            Returns the ending index of the group
        */
        int end(unsigned int group);

        /*
            Returns a string representing the provided groups
        */
        std::string group(unsigned int group);

        /*
            Returns a list of strings representing all capture groups
        */
        std::vector<std::string> groups();

        /*
            Returns the number of groups in the match
        */
        int numGroups();

        friend class Regex;
};

class Regex
{
    private:
        std::string pattern;
        regex_t regex;
        bool compiled;

    public:
        Regex();
        ~Regex();

        /*
            Compiles the provided pattern and returns whether the compilation was successful or not
        */
        bool compile(std::string pattern, bool case_sensitive=true);

        /*
            Returns whether the provided string matches the compiled pattern
        */
        bool matches(std::string str);

        /*
            Returns the first Match in str
        */
        Match match(std::string str);

        /*
            Returns the current compiled pattern in string form
        */
        std::string getPattern();

        /*
            Returns whether there is a current compiled regex in memory
        */
        bool isCompiled();
};

}

#endif
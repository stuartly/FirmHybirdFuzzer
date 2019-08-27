/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* Copy the first part of user declarations.  */
#line 20 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:339  */

#include <stdio.h>

#include "dtc.h"
#include "srcpos.h"

extern int yylex(void);
extern void yyerror(char const *s);
#define ERROR(loc, ...) \
	do { \
		srcpos_error((loc), "Error", __VA_ARGS__); \
		treesource_error = true; \
	} while (0)

extern struct boot_info *the_boot_info;
extern bool treesource_error;

#line 84 "dtc-parser.tab.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "dtc-parser.tab.h".  */
#ifndef YY_YY_DTC_PARSER_TAB_H_INCLUDED
# define YY_YY_DTC_PARSER_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    DT_V1 = 258,
    DT_MEMRESERVE = 259,
    DT_LSHIFT = 260,
    DT_RSHIFT = 261,
    DT_LE = 262,
    DT_GE = 263,
    DT_EQ = 264,
    DT_NE = 265,
    DT_AND = 266,
    DT_OR = 267,
    DT_BITS = 268,
    DT_DEL_PROP = 269,
    DT_DEL_NODE = 270,
    DT_PROPNODENAME = 271,
    DT_LITERAL = 272,
    DT_CHAR_LITERAL = 273,
    DT_BYTE = 274,
    DT_STRING = 275,
    DT_LABEL = 276,
    DT_REF = 277,
    DT_INCBIN = 278
  };
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 38 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:355  */

	char *propnodename;
	char *labelref;
	uint8_t byte;
	struct data data;

	struct {
		struct data	data;
		int		bits;
	} array;

	struct property *prop;
	struct property *proplist;
	struct node *node;
	struct node *nodelist;
	struct reserve_info *re;
	uint64_t integer;

#line 167 "dtc-parser.tab.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif


extern YYSTYPE yylval;
extern YYLTYPE yylloc;
int yyparse (void);

#endif /* !YY_YY_DTC_PARSER_TAB_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 198 "dtc-parser.tab.c" /* yacc.c:358  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
             && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE) + sizeof (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  5
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   137

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  47
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  29
/* YYNRULES -- Number of rules.  */
#define YYNRULES  82
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  146

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   278

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    46,     2,     2,     2,    44,    40,     2,
      32,    34,    43,    41,    33,    42,     2,    25,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    37,    24,
      35,    28,    29,    36,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    30,     2,    31,    39,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    26,    38,    27,    45,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   104,   104,   112,   113,   118,   121,   128,   132,   140,
     144,   149,   160,   170,   185,   193,   196,   203,   207,   211,
     215,   223,   227,   231,   235,   239,   255,   265,   273,   276,
     280,   287,   303,   308,   327,   341,   348,   349,   350,   357,
     361,   362,   366,   367,   371,   372,   376,   377,   381,   382,
     386,   387,   391,   392,   393,   397,   398,   399,   400,   401,
     405,   406,   407,   411,   412,   413,   417,   418,   427,   436,
     440,   441,   442,   443,   448,   451,   455,   463,   466,   470,
     478,   482,   486
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "DT_V1", "DT_MEMRESERVE", "DT_LSHIFT",
  "DT_RSHIFT", "DT_LE", "DT_GE", "DT_EQ", "DT_NE", "DT_AND", "DT_OR",
  "DT_BITS", "DT_DEL_PROP", "DT_DEL_NODE", "DT_PROPNODENAME", "DT_LITERAL",
  "DT_CHAR_LITERAL", "DT_BYTE", "DT_STRING", "DT_LABEL", "DT_REF",
  "DT_INCBIN", "';'", "'/'", "'{'", "'}'", "'='", "'>'", "'['", "']'",
  "'('", "','", "')'", "'<'", "'?'", "':'", "'|'", "'^'", "'&'", "'+'",
  "'-'", "'*'", "'%'", "'~'", "'!'", "$accept", "sourcefile", "v1tag",
  "memreserves", "memreserve", "devicetree", "nodedef", "proplist",
  "propdef", "propdata", "propdataprefix", "arrayprefix", "integer_prim",
  "integer_expr", "integer_trinary", "integer_or", "integer_and",
  "integer_bitor", "integer_bitxor", "integer_bitand", "integer_eq",
  "integer_rela", "integer_shift", "integer_add", "integer_mul",
  "integer_unary", "bytestring", "subnodes", "subnode", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,    59,    47,   123,   125,    61,    62,
      91,    93,    40,    44,    41,    60,    63,    58,   124,    94,
      38,    43,    45,    42,    37,   126,    33
};
# endif

#define YYPACT_NINF -78

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-78)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int8 yypact[] =
{
      16,     1,    41,     9,    16,   -78,    10,     9,    27,     9,
     -78,   -78,   -78,   -11,    10,   -78,    45,    40,   -78,   -11,
     -11,   -11,   -78,    32,   -78,    -3,    62,    18,    38,    43,
      13,     3,    58,     4,    -7,   -78,    66,   -78,   -78,    71,
      72,    45,    45,   -78,   -78,   -78,   -78,   -11,   -11,   -11,
     -11,   -11,   -11,   -11,   -11,   -11,   -11,   -11,   -11,   -11,
     -11,   -11,   -11,   -11,   -11,   -11,   -78,    54,    73,    45,
     -78,   -78,    62,    59,    18,    38,    43,    13,     3,     3,
      58,    58,    58,    58,     4,     4,    -7,    -7,   -78,   -78,
     -78,    79,    82,    50,    54,   -78,    74,    54,   -78,   -78,
     -11,    75,    76,   -78,   -78,   -78,   -78,   -78,    78,   -78,
     -78,   -78,   -78,   -78,    -9,    37,   -78,   -78,   -78,   -78,
      86,   -78,   -78,   -78,    77,   -78,   -78,    22,    69,    85,
      -5,   -78,   -78,   -78,   -78,   -78,    51,   -78,   -78,   -78,
      10,   -78,    80,    10,    81,   -78
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,     0,     5,     3,     1,     0,     0,     0,     5,
       4,    36,    37,     0,     0,     8,     0,     2,     6,     0,
       0,     0,    70,     0,    39,    40,    42,    44,    46,    48,
      50,    52,    55,    62,    65,    69,     0,    15,     9,     0,
       0,     0,     0,    71,    72,    73,    38,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     7,    77,     0,     0,
      12,    10,    43,     0,    45,    47,    49,    51,    53,    54,
      58,    59,    57,    56,    60,    61,    63,    64,    67,    66,
      68,     0,     0,     0,     0,    16,     0,    77,    13,    11,
       0,     0,     0,    18,    28,    80,    20,    82,     0,    79,
      78,    41,    19,    81,     0,     0,    14,    27,    17,    29,
       0,    21,    30,    24,     0,    74,    32,     0,     0,     0,
       0,    35,    34,    22,    33,    31,     0,    75,    76,    23,
       0,    26,     0,     0,     0,    25
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -78,   -78,   102,    98,   101,   -78,   -40,   -78,   -77,   -78,
     -78,   -78,    -6,    63,    12,   -78,    67,    61,    68,    65,
      70,    33,    24,    29,    30,   -16,   -78,    20,    25
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,     3,     8,     9,    17,    38,    67,    95,   114,
     115,   127,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,   130,    96,    97
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      14,    70,    71,    43,    44,    45,    11,    12,    36,    47,
      55,    56,   117,     6,   137,   118,   138,   106,    63,     1,
     109,    13,    53,    54,   119,     4,   139,    11,    12,    99,
       7,    19,    57,    48,    20,    21,    64,    65,    58,    11,
      12,     5,    13,   131,   132,    61,    62,    88,    89,    90,
     120,   133,    16,   105,    13,    39,    50,   121,   122,   123,
     124,    40,    41,    59,    60,    42,    46,   125,    91,    92,
      93,    37,   126,    49,   103,    94,    37,    51,   104,    80,
      81,    82,    83,    52,   140,   141,    78,    79,    84,    85,
      66,    86,    87,    68,    69,   101,   100,    98,   102,   112,
     113,   108,   116,   128,   135,   136,    10,    18,    15,   129,
      74,    73,   111,   143,    72,   145,    76,   110,    75,   107,
       0,   134,    77,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   142,     0,     0,   144
};

static const yytype_int16 yycheck[] =
{
       6,    41,    42,    19,    20,    21,    17,    18,    14,    12,
       7,     8,    21,     4,    19,    24,    21,    94,    25,     3,
      97,    32,     9,    10,    33,    24,    31,    17,    18,    69,
      21,    42,    29,    36,    45,    46,    43,    44,    35,    17,
      18,     0,    32,    21,    22,    41,    42,    63,    64,    65,
      13,    29,    25,    93,    32,    15,    38,    20,    21,    22,
      23,    21,    22,     5,     6,    25,    34,    30,    14,    15,
      16,    26,    35,    11,    24,    21,    26,    39,    28,    55,
      56,    57,    58,    40,    33,    34,    53,    54,    59,    60,
      24,    61,    62,    22,    22,    16,    37,    24,    16,    24,
      24,    27,    24,    17,    35,    20,     4,     9,     7,    32,
      49,    48,   100,    33,    47,    34,    51,    97,    50,    94,
      -1,   127,    52,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   140,    -1,    -1,   143
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     3,    48,    49,    24,     0,     4,    21,    50,    51,
      49,    17,    18,    32,    59,    51,    25,    52,    50,    42,
      45,    46,    59,    60,    61,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    59,    26,    53,    15,
      21,    22,    25,    72,    72,    72,    34,    12,    36,    11,
      38,    39,    40,     9,    10,     7,     8,    29,    35,     5,
       6,    41,    42,    25,    43,    44,    24,    54,    22,    22,
      53,    53,    63,    60,    64,    65,    66,    67,    68,    68,
      69,    69,    69,    69,    70,    70,    71,    71,    72,    72,
      72,    14,    15,    16,    21,    55,    74,    75,    24,    53,
      37,    16,    16,    24,    28,    53,    55,    75,    27,    55,
      74,    61,    24,    24,    56,    57,    24,    21,    24,    33,
      13,    20,    21,    22,    23,    30,    35,    58,    17,    32,
      73,    21,    22,    29,    59,    35,    20,    19,    21,    31,
      33,    34,    59,    33,    59,    34
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    47,    48,    49,    49,    50,    50,    51,    51,    52,
      52,    52,    52,    52,    53,    54,    54,    55,    55,    55,
      55,    56,    56,    56,    56,    56,    56,    56,    57,    57,
      57,    58,    58,    58,    58,    58,    59,    59,    59,    60,
      61,    61,    62,    62,    63,    63,    64,    64,    65,    65,
      66,    66,    67,    67,    67,    68,    68,    68,    68,    68,
      69,    69,    69,    70,    70,    70,    71,    71,    71,    71,
      72,    72,    72,    72,    73,    73,    73,    74,    74,    74,
      75,    75,    75
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     3,     2,     3,     0,     2,     4,     2,     2,
       3,     4,     3,     4,     5,     0,     2,     4,     2,     3,
       2,     2,     3,     4,     2,     9,     5,     2,     0,     2,
       2,     3,     1,     2,     2,     2,     1,     1,     3,     1,
       1,     5,     1,     3,     1,     3,     1,     3,     1,     3,
       1,     3,     1,     3,     3,     1,     3,     3,     3,     3,
       3,     3,     1,     3,     3,     1,     3,     3,     3,     1,
       1,     2,     2,     2,     0,     2,     2,     0,     2,     2,
       2,     3,     2
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static unsigned
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  unsigned res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
 }

#  define YY_LOCATION_PRINT(File, Loc)          \
  yy_location_print_ (File, &(Loc))

# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, Location); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (yylocationp);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  YY_LOCATION_PRINT (yyoutput, *yylocationp);
  YYFPRINTF (yyoutput, ": ");
  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp, int yyrule)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                       , &(yylsp[(yyi + 1) - (yynrhs)])                       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, YYLTYPE *yylocationp)
{
  YYUSE (yyvaluep);
  YYUSE (yylocationp);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Location data for the lookahead symbol.  */
YYLTYPE yylloc
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.
       'yyls': related to locations.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    /* The location stack.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls;
    YYLTYPE *yylsp;

    /* The locations where the error started and ended.  */
    YYLTYPE yyerror_range[3];

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yylsp = yyls = yylsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  yylsp[0] = yylloc;
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yyls1, yysize * sizeof (*yylsp),
                    &yystacksize);

        yyls = yyls1;
        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
  *++yylsp = yylloc;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location.  */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 105 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			the_boot_info = build_boot_info((yyvsp[-1].re), (yyvsp[0].node),
							guess_boot_cpuid((yyvsp[0].node)));
		}
#line 1474 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 5:
#line 118 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.re) = NULL;
		}
#line 1482 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 6:
#line 122 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.re) = chain_reserve_entry((yyvsp[-1].re), (yyvsp[0].re));
		}
#line 1490 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 7:
#line 129 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.re) = build_reserve_entry((yyvsp[-2].integer), (yyvsp[-1].integer));
		}
#line 1498 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 8:
#line 133 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			add_label(&(yyvsp[0].re)->labels, (yyvsp[-1].labelref));
			(yyval.re) = (yyvsp[0].re);
		}
#line 1507 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 9:
#line 141 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.node) = name_node((yyvsp[0].node), "");
		}
#line 1515 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 10:
#line 145 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.node) = merge_nodes((yyvsp[-2].node), (yyvsp[0].node));
		}
#line 1523 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 11:
#line 150 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			struct node *target = get_node_by_ref((yyvsp[-3].node), (yyvsp[-1].labelref));

			add_label(&target->labels, (yyvsp[-2].labelref));
			if (target)
				merge_nodes(target, (yyvsp[0].node));
			else
				ERROR(&(yylsp[-1]), "Label or path %s not found", (yyvsp[-1].labelref));
			(yyval.node) = (yyvsp[-3].node);
		}
#line 1538 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 12:
#line 161 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			struct node *target = get_node_by_ref((yyvsp[-2].node), (yyvsp[-1].labelref));

			if (target)
				merge_nodes(target, (yyvsp[0].node));
			else
				ERROR(&(yylsp[-1]), "Label or path %s not found", (yyvsp[-1].labelref));
			(yyval.node) = (yyvsp[-2].node);
		}
#line 1552 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 13:
#line 171 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			struct node *target = get_node_by_ref((yyvsp[-3].node), (yyvsp[-1].labelref));

			if (target)
				delete_node(target);
			else
				ERROR(&(yylsp[-1]), "Label or path %s not found", (yyvsp[-1].labelref));


			(yyval.node) = (yyvsp[-3].node);
		}
#line 1568 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 14:
#line 186 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.node) = build_node((yyvsp[-3].proplist), (yyvsp[-2].nodelist));
		}
#line 1576 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 15:
#line 193 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.proplist) = NULL;
		}
#line 1584 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 16:
#line 197 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.proplist) = chain_property((yyvsp[0].prop), (yyvsp[-1].proplist));
		}
#line 1592 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 17:
#line 204 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.prop) = build_property((yyvsp[-3].propnodename), (yyvsp[-1].data));
		}
#line 1600 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 18:
#line 208 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.prop) = build_property((yyvsp[-1].propnodename), empty_data);
		}
#line 1608 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 19:
#line 212 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.prop) = build_property_delete((yyvsp[-1].propnodename));
		}
#line 1616 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 20:
#line 216 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			add_label(&(yyvsp[0].prop)->labels, (yyvsp[-1].labelref));
			(yyval.prop) = (yyvsp[0].prop);
		}
#line 1625 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 21:
#line 224 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_merge((yyvsp[-1].data), (yyvsp[0].data));
		}
#line 1633 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 22:
#line 228 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_merge((yyvsp[-2].data), (yyvsp[-1].array).data);
		}
#line 1641 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 23:
#line 232 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_merge((yyvsp[-3].data), (yyvsp[-1].data));
		}
#line 1649 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 24:
#line 236 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_add_marker((yyvsp[-1].data), REF_PATH, (yyvsp[0].labelref));
		}
#line 1657 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 25:
#line 240 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			FILE *f = srcfile_relative_open((yyvsp[-5].data).val, NULL);
			struct data d;

			if ((yyvsp[-3].integer) != 0)
				if (fseek(f, (yyvsp[-3].integer), SEEK_SET) != 0)
					die("Couldn't seek to offset %llu in \"%s\": %s",
					    (unsigned long long)(yyvsp[-3].integer), (yyvsp[-5].data).val,
					    strerror(errno));

			d = data_copy_file(f, (yyvsp[-1].integer));

			(yyval.data) = data_merge((yyvsp[-8].data), d);
			fclose(f);
		}
#line 1677 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 26:
#line 256 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			FILE *f = srcfile_relative_open((yyvsp[-1].data).val, NULL);
			struct data d = empty_data;

			d = data_copy_file(f, -1);

			(yyval.data) = data_merge((yyvsp[-4].data), d);
			fclose(f);
		}
#line 1691 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 27:
#line 266 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_add_marker((yyvsp[-1].data), LABEL, (yyvsp[0].labelref));
		}
#line 1699 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 28:
#line 273 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = empty_data;
		}
#line 1707 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 29:
#line 277 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = (yyvsp[-1].data);
		}
#line 1715 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 30:
#line 281 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_add_marker((yyvsp[-1].data), LABEL, (yyvsp[0].labelref));
		}
#line 1723 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 31:
#line 288 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			unsigned long long bits;

			bits = (yyvsp[-1].integer);

			if ((bits !=  8) && (bits != 16) &&
			    (bits != 32) && (bits != 64)) {
				ERROR(&(yylsp[-1]), "Array elements must be"
				      " 8, 16, 32 or 64-bits");
				bits = 32;
			}

			(yyval.array).data = empty_data;
			(yyval.array).bits = bits;
		}
#line 1743 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 32:
#line 304 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.array).data = empty_data;
			(yyval.array).bits = 32;
		}
#line 1752 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 33:
#line 309 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			if ((yyvsp[-1].array).bits < 64) {
				uint64_t mask = (1ULL << (yyvsp[-1].array).bits) - 1;
				/*
				 * Bits above mask must either be all zero
				 * (positive within range of mask) or all one
				 * (negative and sign-extended). The second
				 * condition is true if when we set all bits
				 * within the mask to one (i.e. | in the
				 * mask), all bits are one.
				 */
				if (((yyvsp[0].integer) > mask) && (((yyvsp[0].integer) | mask) != -1ULL))
					ERROR(&(yylsp[0]), "Value out of range for"
					      " %d-bit array element", (yyvsp[-1].array).bits);
			}

			(yyval.array).data = data_append_integer((yyvsp[-1].array).data, (yyvsp[0].integer), (yyvsp[-1].array).bits);
		}
#line 1775 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 34:
#line 328 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			uint64_t val = ~0ULL >> (64 - (yyvsp[-1].array).bits);

			if ((yyvsp[-1].array).bits == 32)
				(yyvsp[-1].array).data = data_add_marker((yyvsp[-1].array).data,
							  REF_PHANDLE,
							  (yyvsp[0].labelref));
			else
				ERROR(&(yylsp[0]), "References are only allowed in "
					    "arrays with 32-bit elements.");

			(yyval.array).data = data_append_integer((yyvsp[-1].array).data, val, (yyvsp[-1].array).bits);
		}
#line 1793 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 35:
#line 342 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.array).data = data_add_marker((yyvsp[-1].array).data, LABEL, (yyvsp[0].labelref));
		}
#line 1801 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 38:
#line 351 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.integer) = (yyvsp[-1].integer);
		}
#line 1809 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 41:
#line 362 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-4].integer) ? (yyvsp[-2].integer) : (yyvsp[0].integer); }
#line 1815 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 43:
#line 367 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) || (yyvsp[0].integer); }
#line 1821 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 45:
#line 372 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) && (yyvsp[0].integer); }
#line 1827 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 47:
#line 377 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) | (yyvsp[0].integer); }
#line 1833 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 49:
#line 382 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) ^ (yyvsp[0].integer); }
#line 1839 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 51:
#line 387 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) & (yyvsp[0].integer); }
#line 1845 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 53:
#line 392 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) == (yyvsp[0].integer); }
#line 1851 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 54:
#line 393 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) != (yyvsp[0].integer); }
#line 1857 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 56:
#line 398 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) < (yyvsp[0].integer); }
#line 1863 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 57:
#line 399 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) > (yyvsp[0].integer); }
#line 1869 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 58:
#line 400 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) <= (yyvsp[0].integer); }
#line 1875 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 59:
#line 401 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) >= (yyvsp[0].integer); }
#line 1881 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 60:
#line 405 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) << (yyvsp[0].integer); }
#line 1887 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 61:
#line 406 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) >> (yyvsp[0].integer); }
#line 1893 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 63:
#line 411 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) + (yyvsp[0].integer); }
#line 1899 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 64:
#line 412 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) - (yyvsp[0].integer); }
#line 1905 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 66:
#line 417 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = (yyvsp[-2].integer) * (yyvsp[0].integer); }
#line 1911 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 67:
#line 419 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			if ((yyvsp[0].integer) != 0) {
				(yyval.integer) = (yyvsp[-2].integer) / (yyvsp[0].integer);
			} else {
				ERROR(&(yyloc), "Division by zero");
				(yyval.integer) = 0;
			}
		}
#line 1924 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 68:
#line 428 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			if ((yyvsp[0].integer) != 0) {
				(yyval.integer) = (yyvsp[-2].integer) % (yyvsp[0].integer);
			} else {
				ERROR(&(yyloc), "Division by zero");
				(yyval.integer) = 0;
			}
		}
#line 1937 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 71:
#line 441 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = -(yyvsp[0].integer); }
#line 1943 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 72:
#line 442 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = ~(yyvsp[0].integer); }
#line 1949 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 73:
#line 443 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    { (yyval.integer) = !(yyvsp[0].integer); }
#line 1955 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 74:
#line 448 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = empty_data;
		}
#line 1963 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 75:
#line 452 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_append_byte((yyvsp[-1].data), (yyvsp[0].byte));
		}
#line 1971 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 76:
#line 456 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.data) = data_add_marker((yyvsp[-1].data), LABEL, (yyvsp[0].labelref));
		}
#line 1979 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 77:
#line 463 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.nodelist) = NULL;
		}
#line 1987 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 78:
#line 467 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.nodelist) = chain_node((yyvsp[-1].node), (yyvsp[0].nodelist));
		}
#line 1995 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 79:
#line 471 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			ERROR(&(yylsp[0]), "Properties must precede subnodes");
			YYERROR;
		}
#line 2004 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 80:
#line 479 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.node) = name_node((yyvsp[0].node), (yyvsp[-1].propnodename));
		}
#line 2012 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 81:
#line 483 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			(yyval.node) = name_node(build_node_delete(), (yyvsp[-1].propnodename));
		}
#line 2020 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;

  case 82:
#line 487 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1646  */
    {
			add_label(&(yyvsp[0].node)->labels, (yyvsp[-1].labelref));
			(yyval.node) = (yyvsp[0].node);
		}
#line 2029 "dtc-parser.tab.c" /* yacc.c:1646  */
    break;


#line 2033 "dtc-parser.tab.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }

  yyerror_range[1] = yylloc;

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, &yylloc);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  yyerror_range[1] = yylsp[1-yylen];
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, yylsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  /* Using YYLLOC is tempting, but would change the location of
     the lookahead.  YYLOC is available though.  */
  YYLLOC_DEFAULT (yyloc, yyerror_range, 2);
  *++yylsp = yyloc;

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, &yylloc);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, yylsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 493 "/home/stly/Desktop/avatar-panda-ndss/dtc/dtc-parser.y" /* yacc.c:1906  */


void yyerror(char const *s)
{
	ERROR(&yylloc, "%s", s);
}

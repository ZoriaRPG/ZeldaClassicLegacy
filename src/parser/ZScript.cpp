#include "../precompiled.h"
#include "ZScript.h"

#include <sstream>
#include "CompilerUtils.h"
#include "CompileError.h"
#include "DataStructs.h"
#include "Types.h"
#include "Scope.h"

using namespace std;
using namespace ZScript;

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

////////////////////////////////////////////////////////////////
// ZScript::Program

Program::Program(ASTFile& root, CompileErrorHandler* errorHandler)
	: root_(root), rootScope_(new RootScope(typeStore_))
{
	// Create the ~Init script.
	if (Script* initScript =
	    	createScript(
				*this, *rootScope_, ScriptType::global,
				"~Init", errorHandler))
	{
		scripts.push_back(initScript);
		scriptsByName_[initScript->getName()] = initScript;
	}
}

Program::~Program()
{
	deleteElements(scripts);
	delete rootScope_;
}

Script* Program::getScript(string const& name) const
{
	return find<Script*>(scriptsByName_, name).value_or(NULL);
}

Script* Program::getScript(ASTScript* node) const
{
	return find<Script*>(scriptsByNode_, node).value_or(NULL);
}

Script* Program::addScript(
		ASTScript& node, Scope& parentScope, CompileErrorHandler* handler)
{
	Script* script = createScript(*this, parentScope, node, handler);
	if (!script) return NULL;

	scripts.push_back(script);
	scriptsByName_[script->getName()] = script;
	scriptsByNode_[&node] = script;
	return script;
}

vector<Function*> Program::getUserGlobalFunctions() const
{
	vector<Function*> functions = rootScope_->getLocalFunctions();
	for (vector<Function*>::iterator it = functions.begin();
	     it != functions.end();)
	{
		Function& function = **it;
		if (!function.node) it = functions.erase(it);
		else ++it;
	}
	return functions;
}

vector<Function*> Program::getUserFunctions() const
{
	vector<Function*> functions = getFunctions(*this);
	for (vector<Function*>::iterator it = functions.begin();
	     it != functions.end();)
	{
		Function& function = **it;
		if (!function.node) it = functions.erase(it);
		else ++it;
	}
	return functions;
}

vector<Function*> ZScript::getFunctions(Program const& program)
{
	vector<Function*> functions = getFunctionsInBranch(program.getScope());
	appendElements(functions, getClassFunctions(program.getTypeStore()));
	return functions;
}

////////////////////////////////////////////////////////////////
// ZScript::Script

// ZScript::Script

Script::Script(Program& program) : program(program) {}

Script::~Script()
{
	deleteElements(code);
}

// ZScript::UserScript

UserScript::UserScript(Program& program, ASTScript& node)
	: Script(program), node(node)
{}

ScriptType UserScript::getType() const
{
	return resolveScriptType(*node.type, *scope->getParent());
}

// ZScript::BuiltinScript

BuiltinScript::BuiltinScript(
		Program& program, ScriptType type, string const& name)
	: Script(program), type(type), name(name)
{}

// ZScript

UserScript* ZScript::createScript(
		Program& program, Scope& parentScope, ASTScript& node,
		CompileErrorHandler* errorHandler)
{
	UserScript* script = new UserScript(program, node);

	ScriptScope* scope = parentScope.makeScriptChild(*script);
	if (!scope)
	{
		if (errorHandler)
			errorHandler->handleError(
				CompileError::ScriptRedef(&node, node.name));
		delete script;
		return NULL;
	}
	script->scope = scope;

	if (!resolveScriptType(*node.type, parentScope).isValid())
	{
		if (errorHandler)
			errorHandler->handleError(
				CompileError::ScriptBadType(&node, node.name));
		delete script;
		return NULL;
	}

	return script;
}

BuiltinScript* ZScript::createScript(
		Program& program, Scope& parentScope, ScriptType type,
		string const& name, CompileErrorHandler* errorHandler)
{
	BuiltinScript* script = new BuiltinScript(program, type, name);

	ScriptScope* scope = parentScope.makeScriptChild(*script);
	if (!scope)
	{
		if (errorHandler)
			errorHandler->handleError(CompileError::ScriptRedef(NULL, name));
		delete script;
		return NULL;
	}
	script->scope = scope;

	if (!type.isValid())
	{
		if (errorHandler)
			errorHandler->handleError(
				CompileError::ScriptBadType(NULL, name));
		delete script;
		return NULL;
	}

	return script;
}

Function* ZScript::getRunFunction(Script const& script)
{
	return getOnly<Function*>(script.getScope().getLocalFunctions("run"))
		.value_or(NULL);
}

optional<int> ZScript::getLabel(Script const& script)
{
	if (Function* run = getRunFunction(script))
		return run->getLabel();
	return nullopt;
}

////////////////////////////////////////////////////////////////
// ZScript::Datum

Datum::Datum(Scope& scope, DataType const& type)
	: scope(scope), type(type), id(ScriptParser::getUniqueVarID())
{}

bool Datum::tryAddToScope(CompileErrorHandler* errorHandler)
{
	return scope.add(*this, errorHandler);
}

bool ZScript::isGlobal(Datum const& datum)
{
	return (datum.scope.isGlobal() || datum.scope.isScript())
		&& datum.getName();
}

optional<int> ZScript::getStackOffset(Datum const& datum)
{
	return lookupStackPosition(datum.scope, datum);
}

// ZScript::Literal

Literal* Literal::create(
		Scope& scope, ASTLiteral& node, DataType const& type,
		CompileErrorHandler* errorHandler)
{
	Literal* literal = new Literal(scope, node, type);
	if (literal->tryAddToScope(errorHandler)) return literal;
	delete literal;
	return NULL;
}

Literal::Literal(Scope& scope, ASTLiteral& node, DataType const& type)
	: Datum(scope, type), node(node)
{
	node.manager = this;
}

// ZScript::Variable

Variable* Variable::create(
		Scope& scope, ASTDataDecl& node, DataType const& type,
		CompileErrorHandler* errorHandler)
{
	Variable* variable = new Variable(scope, node, type);
	if (variable->tryAddToScope(errorHandler)) return variable;
	delete variable;
	return NULL;
}

Variable::Variable(
		Scope& scope, ASTDataDecl& node, DataType const& type)
	: Datum(scope, type),
	  node(node),
	  globalId((scope.isGlobal() || scope.isScript())
	           ? optional<int>(ScriptParser::getUniqueGlobalID())
	           : nullopt)
{
	node.manager = this;
}

// ZScript::BuiltinVariable

BuiltinVariable* BuiltinVariable::create(
		Scope& scope, DataType const& type, string const& name,
		CompileErrorHandler* errorHandler)
{
	BuiltinVariable* builtin = new BuiltinVariable(scope, type, name);
	if (builtin->tryAddToScope(errorHandler)) return builtin;
	delete builtin;
	return NULL;
}

BuiltinVariable::BuiltinVariable(
		Scope& scope, DataType const& type, string const& name)
	: Datum(scope, type),
	  name(name),
	  globalId((scope.isGlobal() || scope.isScript())
	           ? optional<int>(ScriptParser::getUniqueGlobalID())
	           : nullopt)
{}

// ZScript::Constant

Constant* Constant::create(
		Scope& scope, ASTDataDecl& node, DataType const& type, long value,
		CompileErrorHandler* errorHandler)
{
	Constant* constant = new Constant(scope, node, type, value);
	if (constant->tryAddToScope(errorHandler)) return constant;
	delete constant;
	return NULL;
}

Constant::Constant(
		Scope& scope, ASTDataDecl& node, DataType const& type, long value)
	: Datum(scope, type), node(node), value(value)
{
	node.manager = this;
}

optional<string> Constant::getName() const {return node.name;}

// ZScript::BuiltinConstant


BuiltinConstant* BuiltinConstant::create(
		Scope& scope, DataType const& type, string const& name, long value,
		CompileErrorHandler* errorHandler)
{
	BuiltinConstant* builtin = new BuiltinConstant(scope, type, name, value);
	if (builtin->tryAddToScope(errorHandler)) return builtin;
	delete builtin;
	return NULL;
}

BuiltinConstant::BuiltinConstant(
		Scope& scope, DataType const& type, string const& name, long value)
	: Datum(scope, type), name(name), value(value)
{}

// ZScript::FunctionSignature

FunctionSignature::FunctionSignature(
		string const& name, vector<DataType const*> const& parameterTypes)
	: name(name), parameterTypes(parameterTypes)
{}

FunctionSignature::FunctionSignature(Function const& function)
	: name(function.name), parameterTypes(function.paramTypes)
{}
		
int FunctionSignature::compare(FunctionSignature const& other) const
{
	int c = name.compare(other.name);
	if (c) return c;
	c = parameterTypes.size() - other.parameterTypes.size();
	if (c) return c;
	for (int i = 0; i < (int)parameterTypes.size(); ++i)
	{
		c = parameterTypes[i]->compare(*other.parameterTypes[i]);
		if (c) return c;
	}
	return 0;
}

bool FunctionSignature::operator==(FunctionSignature const& other) const
{
	return compare(other) == 0;
}

bool FunctionSignature::operator<(FunctionSignature const& other) const
{
	return compare(other) < 0;
}

string FunctionSignature::asString() const
{
	ostringstream oss;
	oss << name << "(";
	for (vector<DataType const*>::const_iterator it = parameterTypes.begin();
		 it != parameterTypes.end(); ++it)
	{
		if (it != parameterTypes.begin()) oss << ", ";
		oss << (*it)->getName();
	}
	oss << ")";
	return oss.str();
}

// ZScript::Function

Function::Function(DataType const* returnType, string const& name,
				   vector<DataType const*> paramTypes, int id)
	: node(NULL), internalScope(NULL), thisVar(NULL),
	  returnType(returnType), name(name), paramTypes(paramTypes),
	  id(id), label(nullopt)
{}

Function::~Function()
{
	deleteElements(ownedCode);
}

vector<Opcode*> Function::takeCode()
{
	vector<Opcode*> code = ownedCode;
	ownedCode.clear();
	return code;
}

void Function::giveCode(vector<Opcode*>& code)
{
	appendElements(ownedCode, code);
	code.clear();
}

Script* Function::getScript() const
{
	if (!internalScope) return NULL;
	Scope* parentScope = internalScope->getParent();
	if (!parentScope) return NULL;
	if (!parentScope->isScript()) return NULL;
	ScriptScope* scriptScope =
		dynamic_cast<ScriptScope*>(parentScope);
	return &scriptScope->script;
}

int Function::getLabel() const
{
	if (!label) label = ScriptParser::getUniqueLabelID();
	return *label;
}

bool Function::isTracing() const
{
	std::string prefix = name.substr(0, 5);
	return *returnType == DataType::ZVOID
		&& (prefix == "Trace" || prefix == "print");
}

bool ZScript::isRun(Function const& function)
{
	return function.internalScope->getParent()->isScript()
		&& *function.returnType == DataType::ZVOID
		&& function.name == "run";
}

int ZScript::getStackSize(Function const& function)
{
	return *lookupStackSize(*function.internalScope);
}

int ZScript::getParameterCount(Function const& function)
{
	return function.paramTypes.size() + (isRun(function) ? 1 : 0);
}

using namespace std;
using namespace POSIX;

////////////////////// Start Match Implementations //////////////////////

Match::Match()
{
    match = "";
}

Match::Match(string match)
{
    this->match = match;
}

int Match::start(unsigned int group)
{
    if (group >= pgroups.size())
        return -1;

    return pgroups[group].start;
}

int Match::end(unsigned int group)
{
    if (group >= pgroups.size())
        return -1;

    return pgroups[group].end;
}

string Match::group(unsigned int group)
{
    if (group >= pgroups.size())
        return "";

    if (pgroups[group].start == -1 || pgroups[group].end == -1)
        return "";
    
    return match.substr(pgroups[group].start, pgroups[group].end - pgroups[group].start);
}

vector<string> Match::groups()
{
    vector<string> g;

    for (unsigned int i = 0; i < pgroups.size(); i++)
    {
        if (pgroups[i].start >= 0 && pgroups[i].end >= 0)
            g.push_back(match.substr(pgroups[i].start, pgroups[i].end - pgroups[i].start));
    }

    return g;
}

int Match::numGroups()
{
    return pgroups.size();
}

void Match::addGroup(int start, int end)
{
    Group g = {start, end};
    pgroups.push_back(g);
}

////////////////////// Start Regex Implementations //////////////////////

#ifdef _LIBC
/* We have to keep the namespace clean.  */
# define regfree(preg) __regfree (preg)
# define regexec(pr, st, nm, pm, ef) __regexec (pr, st, nm, pm, ef)
# define regcomp(preg, pattern, cflags) __regcomp (preg, pattern, cflags)
# define regerror(errcode, preg, errbuf, errbuf_size) \
	__regerror(errcode, preg, errbuf, errbuf_size)
# define re_set_registers(bu, re, nu, st, en) \
	__re_set_registers (bu, re, nu, st, en)
# define re_match_2(bufp, string1, size1, string2, size2, pos, regs, stop) \
	__re_match_2 (bufp, string1, size1, string2, size2, pos, regs, stop)
# define re_match(bufp, string, size, pos, regs) \
	__re_match (bufp, string, size, pos, regs)
# define re_search(bufp, string, size, startpos, range, regs) \
	__re_search (bufp, string, size, startpos, range, regs)
# define re_compile_pattern(pattern, length, bufp) \
	__re_compile_pattern (pattern, length, bufp)
# define re_set_syntax(syntax) __re_set_syntax (syntax)
# define re_search_2(bufp, st1, s1, st2, s2, startpos, range, regs, stop) \
	__re_search_2 (bufp, st1, s1, st2, s2, startpos, range, regs, stop)
# define re_compile_fastmap(bufp) __re_compile_fastmap (bufp)

# include "../locale/localeinfo.h"
#endif

#if defined (_MSC_VER)
//#include <stdio.h> /* for size_t */
#endif

/* On some systems, limits.h sets RE_DUP_MAX to a lower value than
   GNU regex allows.  Include it before <regex.h>, which correctly
   #undefs RE_DUP_MAX and sets it to the right value.  */
#include <limits.h>

#ifdef GAWK
#undef alloca
#define alloca alloca_is_bad_you_should_never_use_it
#endif

static void re_string_construct_common (const char *str, int len,
					re_string_t *pstr,
					RE_TRANSLATE_TYPE trans, int icase,
					const re_dfa_t *dfa) internal_function;
static re_dfastate_t *create_ci_newstate (const re_dfa_t *dfa,
					  const re_node_set *nodes,
					  unsigned int hash) internal_function;
static re_dfastate_t *create_cd_newstate (const re_dfa_t *dfa,
					  const re_node_set *nodes,
					  unsigned int context,
					  unsigned int hash) internal_function;

#ifdef GAWK
#undef MAX	/* safety */
static size_t
MAX(size_t a, size_t b)
{
	return (a > b ? a : b);
}
#endif

/* Functions for string operation.  */

/* This function allocate the buffers.  It is necessary to call
   re_string_reconstruct before using the object.  */

static reg_errcode_t
internal_function
re_string_allocate (re_string_t *pstr, const char *str, int len, int init_len,
		    RE_TRANSLATE_TYPE trans, int icase, const re_dfa_t *dfa)
{
  reg_errcode_t ret;
  int init_buf_len;

  /* Ensure at least one character fits into the buffers.  */
  if (init_len < dfa->mb_cur_max)
    init_len = dfa->mb_cur_max;
  init_buf_len = (len + 1 < init_len) ? len + 1: init_len;
  re_string_construct_common (str, len, pstr, trans, icase, dfa);

  ret = re_string_realloc_buffers (pstr, init_buf_len);
  if (BE (ret != REG_NOERROR, 0))
    return ret;

  pstr->word_char = dfa->word_char;
  pstr->word_ops_used = dfa->word_ops_used;
  pstr->mbs = pstr->mbs_allocated ? pstr->mbs : (unsigned char *) str;
  pstr->valid_len = (pstr->mbs_allocated || dfa->mb_cur_max > 1) ? 0 : len;
  pstr->valid_raw_len = pstr->valid_len;
  return REG_NOERROR;
}

/* This function allocate the buffers, and initialize them.  */

static reg_errcode_t
internal_function
re_string_construct (re_string_t *pstr, const char *str, int len,
		     RE_TRANSLATE_TYPE trans, int icase, const re_dfa_t *dfa)
{
  reg_errcode_t ret;
  memset (pstr, '\0', sizeof (re_string_t));
  re_string_construct_common (str, len, pstr, trans, icase, dfa);

  if (len > 0)
    {
      ret = re_string_realloc_buffers (pstr, len + 1);
      if (BE (ret != REG_NOERROR, 0))
	return ret;
    }
  pstr->mbs = pstr->mbs_allocated ? pstr->mbs : (unsigned char *) str;

  if (icase)
    {
#ifdef RE_ENABLE_I18N
      if (dfa->mb_cur_max > 1)
	{
	  while (1)
	    {
	      ret = build_wcs_upper_buffer (pstr);
	      if (BE (ret != REG_NOERROR, 0))
		return ret;
	      if (pstr->valid_raw_len >= len)
		break;
	      if (pstr->bufs_len > pstr->valid_len + dfa->mb_cur_max)
		break;
	      ret = re_string_realloc_buffers (pstr, pstr->bufs_len * 2);
	      if (BE (ret != REG_NOERROR, 0))
		return ret;
	    }
	}
      else
#endif /* RE_ENABLE_I18N  */
	build_upper_buffer (pstr);
    }
  else
    {
#ifdef RE_ENABLE_I18N
      if (dfa->mb_cur_max > 1)
	build_wcs_buffer (pstr);
      else
#endif /* RE_ENABLE_I18N  */
	{
	  if (trans != NULL)
	    re_string_translate_buffer (pstr);
	  else
	    {
	      pstr->valid_len = pstr->bufs_len;
	      pstr->valid_raw_len = pstr->bufs_len;
	    }
	}
    }

  return REG_NOERROR;
}

/* Helper functions for re_string_allocate, and re_string_construct.  */

static reg_errcode_t
internal_function
re_string_realloc_buffers (re_string_t *pstr, int new_buf_len)
{
#ifdef RE_ENABLE_I18N
  if (pstr->mb_cur_max > 1)
    {
      wint_t *new_wcs;

      /* Avoid overflow in realloc.  */
      const size_t max_object_size = MAX (sizeof (wint_t), sizeof (int));
      if (BE (SIZE_MAX / max_object_size < new_buf_len, 0))
	return REG_ESPACE;

      new_wcs = re_realloc (pstr->wcs, wint_t, new_buf_len);
      if (BE (new_wcs == NULL, 0))
	return REG_ESPACE;
      pstr->wcs = new_wcs;
      if (pstr->offsets != NULL)
	{
	  int *new_offsets = re_realloc (pstr->offsets, int, new_buf_len);
	  if (BE (new_offsets == NULL, 0))
	    return REG_ESPACE;
	  pstr->offsets = new_offsets;
	}
    }
#endif /* RE_ENABLE_I18N  */
  if (pstr->mbs_allocated)
    {
      unsigned char *new_mbs = re_realloc (pstr->mbs, unsigned char,
					   new_buf_len);
      if (BE (new_mbs == NULL, 0))
	return REG_ESPACE;
      pstr->mbs = new_mbs;
    }
  pstr->bufs_len = new_buf_len;
  return REG_NOERROR;
}


static void
internal_function
re_string_construct_common (const char *str, int len, re_string_t *pstr,
			    RE_TRANSLATE_TYPE trans, int icase,
			    const re_dfa_t *dfa)
{
  pstr->raw_mbs = (const unsigned char *) str;
  pstr->len = len;
  pstr->raw_len = len;
  pstr->trans = trans;
  pstr->icase = icase ? 1 : 0;
  pstr->mbs_allocated = (trans != NULL || icase);
  pstr->mb_cur_max = dfa->mb_cur_max;
  pstr->is_utf8 = dfa->is_utf8;
  pstr->map_notascii = dfa->map_notascii;
  pstr->stop = pstr->len;
  pstr->raw_stop = pstr->stop;
}

#ifdef RE_ENABLE_I18N

/* Build wide character buffer PSTR->WCS.
   If the byte sequence of the string are:
     <mb1>(0), <mb1>(1), <mb2>(0), <mb2>(1), <sb3>
   Then wide character buffer will be:
     <wc1>   , WEOF    , <wc2>   , WEOF    , <wc3>
   We use WEOF for padding, they indicate that the position isn't
   a first byte of a multibyte character.

   Note that this function assumes PSTR->VALID_LEN elements are already
   built and starts from PSTR->VALID_LEN.  */

static void
internal_function
build_wcs_buffer (re_string_t *pstr)
{
#ifdef _LIBC
  unsigned char buf[MB_LEN_MAX];
  assert (MB_LEN_MAX >= pstr->mb_cur_max);
#else
  unsigned char buf[64];
#endif
  mbstate_t prev_st;
  int byte_idx, end_idx, remain_len;
  size_t mbclen;

  /* Build the buffers from pstr->valid_len to either pstr->len or
     pstr->bufs_len.  */
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;
  for (byte_idx = pstr->valid_len; byte_idx < end_idx;)
    {
      wchar_t wc;
      const char *p;

      remain_len = end_idx - byte_idx;
      prev_st = pstr->cur_state;
      /* Apply the translation if we need.  */
      if (BE (pstr->trans != NULL, 0))
	{
	  int i, ch;

	  for (i = 0; i < pstr->mb_cur_max && i < remain_len; ++i)
	    {
	      ch = pstr->raw_mbs [pstr->raw_mbs_idx + byte_idx + i];
	      buf[i] = pstr->mbs[byte_idx + i] = pstr->trans[ch];
	    }
	  p = (const char *) buf;
	}
      else
	p = (const char *) pstr->raw_mbs + pstr->raw_mbs_idx + byte_idx;
      mbclen = __mbrtowc (&wc, p, remain_len, &pstr->cur_state);
      if (BE (mbclen == (size_t) -2, 0))
	{
	  /* The buffer doesn't have enough space, finish to build.  */
	  pstr->cur_state = prev_st;
	  break;
	}
      else if (BE (mbclen == (size_t) -1 || mbclen == 0, 0))
	{
	  /* We treat these cases as a singlebyte character.  */
	  mbclen = 1;
	  wc = (wchar_t) pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx];
	  if (BE (pstr->trans != NULL, 0))
	    wc = pstr->trans[wc];
	  pstr->cur_state = prev_st;
	}

      /* Write wide character and padding.  */
      pstr->wcs[byte_idx++] = wc;
      /* Write paddings.  */
      for (remain_len = byte_idx + mbclen - 1; byte_idx < remain_len ;)
	pstr->wcs[byte_idx++] = WEOF;
    }
  pstr->valid_len = byte_idx;
  pstr->valid_raw_len = byte_idx;
}

/* Build wide character buffer PSTR->WCS like build_wcs_buffer,
   but for REG_ICASE.  */

static reg_errcode_t
internal_function
build_wcs_upper_buffer (re_string_t *pstr)
{
  mbstate_t prev_st;
  int src_idx, byte_idx, end_idx, remain_len;
  size_t mbclen;
#ifdef _LIBC
  char buf[MB_LEN_MAX];
  assert (MB_LEN_MAX >= pstr->mb_cur_max);
#else
  char buf[64];
#endif

  byte_idx = pstr->valid_len;
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;

  /* The following optimization assumes that ASCII characters can be
     mapped to wide characters with a simple cast.  */
  if (! pstr->map_notascii && pstr->trans == NULL && !pstr->offsets_needed)
    {
      while (byte_idx < end_idx)
	{
	  wchar_t wc;

	  if (isascii (pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx])
	      && mbsinit (&pstr->cur_state))
	    {
	      /* In case of a singlebyte character.  */
	      pstr->mbs[byte_idx]
		= toupper (pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx]);
	      /* The next step uses the assumption that wchar_t is encoded
		 ASCII-safe: all ASCII values can be converted like this.  */
	      pstr->wcs[byte_idx] = (wchar_t) pstr->mbs[byte_idx];
	      ++byte_idx;
	      continue;
	    }

	  remain_len = end_idx - byte_idx;
	  prev_st = pstr->cur_state;
	  mbclen = __mbrtowc (&wc,
			      ((const char *) pstr->raw_mbs + pstr->raw_mbs_idx
			       + byte_idx), remain_len, &pstr->cur_state);
	  if (BE (mbclen + 2 > 2, 1))
	    {
	      wchar_t wcu = wc;
	      if (iswlower (wc))
		{
		  size_t mbcdlen;

		  wcu = towupper (wc);
		  mbcdlen = wcrtomb (buf, wcu, &prev_st);
		  if (BE (mbclen == mbcdlen, 1))
		    memcpy (pstr->mbs + byte_idx, buf, mbclen);
		  else
		    {
		      src_idx = byte_idx;
		      goto offsets_needed;
		    }
		}
	      else
		memcpy (pstr->mbs + byte_idx,
			pstr->raw_mbs + pstr->raw_mbs_idx + byte_idx, mbclen);
	      pstr->wcs[byte_idx++] = wcu;
	      /* Write paddings.  */
	      for (remain_len = byte_idx + mbclen - 1; byte_idx < remain_len ;)
		pstr->wcs[byte_idx++] = WEOF;
	    }
	  else if (mbclen == (size_t) -1 || mbclen == 0)
	    {
	      /* It is an invalid character or '\0'.  Just use the byte.  */
	      int ch = pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx];
	      pstr->mbs[byte_idx] = ch;
	      /* And also cast it to wide char.  */
	      pstr->wcs[byte_idx++] = (wchar_t) ch;
	      if (BE (mbclen == (size_t) -1, 0))
		pstr->cur_state = prev_st;
	    }
	  else
	    {
	      /* The buffer doesn't have enough space, finish to build.  */
	      pstr->cur_state = prev_st;
	      break;
	    }
	}
      pstr->valid_len = byte_idx;
      pstr->valid_raw_len = byte_idx;
      return REG_NOERROR;
    }
  else
    for (src_idx = pstr->valid_raw_len; byte_idx < end_idx;)
      {
	wchar_t wc;
	const char *p;
      offsets_needed:
	remain_len = end_idx - byte_idx;
	prev_st = pstr->cur_state;
	if (BE (pstr->trans != NULL, 0))
	  {
	    int i, ch;

	    for (i = 0; i < pstr->mb_cur_max && i < remain_len; ++i)
	      {
		ch = pstr->raw_mbs [pstr->raw_mbs_idx + src_idx + i];
		buf[i] = pstr->trans[ch];
	      }
	    p = (const char *) buf;
	  }
	else
	  p = (const char *) pstr->raw_mbs + pstr->raw_mbs_idx + src_idx;
	mbclen = __mbrtowc (&wc, p, remain_len, &pstr->cur_state);
	if (BE (mbclen + 2 > 2, 1))
	  {
	    wchar_t wcu = wc;
	    if (iswlower (wc))
	      {
		size_t mbcdlen;

		wcu = towupper (wc);
		mbcdlen = wcrtomb ((char *) buf, wcu, &prev_st);
		if (BE (mbclen == mbcdlen, 1))
		  memcpy (pstr->mbs + byte_idx, buf, mbclen);
		else if (mbcdlen != (size_t) -1)
		  {
		    size_t i;

		    if (byte_idx + mbcdlen > pstr->bufs_len)
		      {
			pstr->cur_state = prev_st;
			break;
		      }

		    if (pstr->offsets == NULL)
		      {
			pstr->offsets = re_malloc (int, pstr->bufs_len);

			if (pstr->offsets == NULL)
			  return REG_ESPACE;
		      }
		    if (!pstr->offsets_needed)
		      {
			for (i = 0; i < (size_t) byte_idx; ++i)
			  pstr->offsets[i] = i;
			pstr->offsets_needed = 1;
		      }

		    memcpy (pstr->mbs + byte_idx, buf, mbcdlen);
		    pstr->wcs[byte_idx] = wcu;
		    pstr->offsets[byte_idx] = src_idx;
		    for (i = 1; i < mbcdlen; ++i)
		      {
			pstr->offsets[byte_idx + i]
			  = src_idx + (i < mbclen ? i : mbclen - 1);
			pstr->wcs[byte_idx + i] = WEOF;
		      }
		    pstr->len += mbcdlen - mbclen;
		    if (pstr->raw_stop > src_idx)
		      pstr->stop += mbcdlen - mbclen;
		    end_idx = (pstr->bufs_len > pstr->len)
			      ? pstr->len : pstr->bufs_len;
		    byte_idx += mbcdlen;
		    src_idx += mbclen;
		    continue;
		  }
		else
		  memcpy (pstr->mbs + byte_idx, p, mbclen);
	      }
	    else
	      memcpy (pstr->mbs + byte_idx, p, mbclen);

	    if (BE (pstr->offsets_needed != 0, 0))
	      {
		size_t i;
		for (i = 0; i < mbclen; ++i)
		  pstr->offsets[byte_idx + i] = src_idx + i;
	      }
	    src_idx += mbclen;

	    pstr->wcs[byte_idx++] = wcu;
	    /* Write paddings.  */
	    for (remain_len = byte_idx + mbclen - 1; byte_idx < remain_len ;)
	      pstr->wcs[byte_idx++] = WEOF;
	  }
	else if (mbclen == (size_t) -1 || mbclen == 0)
	  {
	    /* It is an invalid character or '\0'.  Just use the byte.  */
	    int ch = pstr->raw_mbs[pstr->raw_mbs_idx + src_idx];

	    if (BE (pstr->trans != NULL, 0))
	      ch = pstr->trans [ch];
	    pstr->mbs[byte_idx] = ch;

	    if (BE (pstr->offsets_needed != 0, 0))
	      pstr->offsets[byte_idx] = src_idx;
	    ++src_idx;

	    /* And also cast it to wide char.  */
	    pstr->wcs[byte_idx++] = (wchar_t) ch;
	    if (BE (mbclen == (size_t) -1, 0))
	      pstr->cur_state = prev_st;
	  }
	else
	  {
	    /* The buffer doesn't have enough space, finish to build.  */
	    pstr->cur_state = prev_st;
	    break;
	  }
      }
  pstr->valid_len = byte_idx;
  pstr->valid_raw_len = src_idx;
  return REG_NOERROR;
}

/* Skip characters until the index becomes greater than NEW_RAW_IDX.
   Return the index.  */

static int
internal_function
re_string_skip_chars (re_string_t *pstr, int new_raw_idx, wint_t *last_wc)
{
  mbstate_t prev_st;
  int rawbuf_idx;
  size_t mbclen;
  wint_t wc = WEOF;

  /* Skip the characters which are not necessary to check.  */
  for (rawbuf_idx = pstr->raw_mbs_idx + pstr->valid_raw_len;
       rawbuf_idx < new_raw_idx;)
    {
      wchar_t wc2;
      int remain_len = pstr->len - rawbuf_idx;
      prev_st = pstr->cur_state;
      mbclen = __mbrtowc (&wc2, (const char *) pstr->raw_mbs + rawbuf_idx,
			  remain_len, &pstr->cur_state);
      if (BE (mbclen == (size_t) -2 || mbclen == (size_t) -1 || mbclen == 0, 0))
	{
	  /* We treat these cases as a single byte character.  */
	  if (mbclen == 0 || remain_len == 0)
	    wc = L'\0';
	  else
	    wc = *(unsigned char *) (pstr->raw_mbs + rawbuf_idx);
	  mbclen = 1;
	  pstr->cur_state = prev_st;
	}
      else
	wc = (wint_t) wc2;
      /* Then proceed the next character.  */
      rawbuf_idx += mbclen;
    }
  *last_wc = (wint_t) wc;
  return rawbuf_idx;
}
#endif /* RE_ENABLE_I18N  */

/* Build the buffer PSTR->MBS, and apply the translation if we need.
   This function is used in case of REG_ICASE.  */

static void
internal_function
build_upper_buffer (re_string_t *pstr)
{
  int char_idx, end_idx;
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;

  for (char_idx = pstr->valid_len; char_idx < end_idx; ++char_idx)
    {
      int ch = pstr->raw_mbs[pstr->raw_mbs_idx + char_idx];
      if (BE (pstr->trans != NULL, 0))
	ch = pstr->trans[ch];
      if (islower (ch))
	pstr->mbs[char_idx] = toupper (ch);
      else
	pstr->mbs[char_idx] = ch;
    }
  pstr->valid_len = char_idx;
  pstr->valid_raw_len = char_idx;
}

/* Apply TRANS to the buffer in PSTR.  */

static void
internal_function
re_string_translate_buffer (re_string_t *pstr)
{
  int buf_idx, end_idx;
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;

  for (buf_idx = pstr->valid_len; buf_idx < end_idx; ++buf_idx)
    {
      int ch = pstr->raw_mbs[pstr->raw_mbs_idx + buf_idx];
      pstr->mbs[buf_idx] = pstr->trans[ch];
    }

  pstr->valid_len = buf_idx;
  pstr->valid_raw_len = buf_idx;
}

/* This function re-construct the buffers.
   Concretely, convert to wide character in case of pstr->mb_cur_max > 1,
   convert to upper case in case of REG_ICASE, apply translation.  */

static reg_errcode_t
internal_function
re_string_reconstruct (re_string_t *pstr, int idx, int eflags)
{
  int offset = idx - pstr->raw_mbs_idx;
  if (BE (offset < 0, 0))
    {
      /* Reset buffer.  */
#ifdef RE_ENABLE_I18N
      if (pstr->mb_cur_max > 1)
	memset (&pstr->cur_state, '\0', sizeof (mbstate_t));
#endif /* RE_ENABLE_I18N */
      pstr->len = pstr->raw_len;
      pstr->stop = pstr->raw_stop;
      pstr->valid_len = 0;
      pstr->raw_mbs_idx = 0;
      pstr->valid_raw_len = 0;
      pstr->offsets_needed = 0;
      pstr->tip_context = ((eflags & REG_NOTBOL) ? CONTEXT_BEGBUF
			   : CONTEXT_NEWLINE | CONTEXT_BEGBUF);
      if (!pstr->mbs_allocated)
	pstr->mbs = (unsigned char *) pstr->raw_mbs;
      offset = idx;
    }

  if (BE (offset != 0, 1))
    {
      /* Should the already checked characters be kept?  */
      if (BE (offset < pstr->valid_raw_len, 1))
	{
	  /* Yes, move them to the front of the buffer.  */
#ifdef RE_ENABLE_I18N
	  if (BE (pstr->offsets_needed, 0))
	    {
	      int low = 0, high = pstr->valid_len, mid;
	      do
		{
		  mid = (high + low) / 2;
		  if (pstr->offsets[mid] > offset)
		    high = mid;
		  else if (pstr->offsets[mid] < offset)
		    low = mid + 1;
		  else
		    break;
		}
	      while (low < high);
	      if (pstr->offsets[mid] < offset)
		++mid;
	      pstr->tip_context = re_string_context_at (pstr, mid - 1,
							eflags);
	      /* This can be quite complicated, so handle specially
		 only the common and easy case where the character with
		 different length representation of lower and upper
		 case is present at or after offset.  */
	      if (pstr->valid_len > offset
		  && mid == offset && pstr->offsets[mid] == offset)
		{
		  memmove (pstr->wcs, pstr->wcs + offset,
			   (pstr->valid_len - offset) * sizeof (wint_t));
		  memmove (pstr->mbs, pstr->mbs + offset, pstr->valid_len - offset);
		  pstr->valid_len -= offset;
		  pstr->valid_raw_len -= offset;
		  for (low = 0; low < pstr->valid_len; low++)
		    pstr->offsets[low] = pstr->offsets[low + offset] - offset;
		}
	      else
		{
		  /* Otherwise, just find out how long the partial multibyte
		     character at offset is and fill it with WEOF/255.  */
		  pstr->len = pstr->raw_len - idx + offset;
		  pstr->stop = pstr->raw_stop - idx + offset;
		  pstr->offsets_needed = 0;
		  while (mid > 0 && pstr->offsets[mid - 1] == offset)
		    --mid;
		  while (mid < pstr->valid_len)
		    if (pstr->wcs[mid] != WEOF)
		      break;
		    else
		      ++mid;
		  if (mid == pstr->valid_len)
		    pstr->valid_len = 0;
		  else
		    {
		      pstr->valid_len = pstr->offsets[mid] - offset;
		      if (pstr->valid_len)
			{
			  for (low = 0; low < pstr->valid_len; ++low)
			    pstr->wcs[low] = WEOF;
			  memset (pstr->mbs, 255, pstr->valid_len);
			}
		    }
		  pstr->valid_raw_len = pstr->valid_len;
		}
	    }
	  else
#endif
	    {
	      pstr->tip_context = re_string_context_at (pstr, offset - 1,
							eflags);
#ifdef RE_ENABLE_I18N
	      if (pstr->mb_cur_max > 1)
		memmove (pstr->wcs, pstr->wcs + offset,
			 (pstr->valid_len - offset) * sizeof (wint_t));
#endif /* RE_ENABLE_I18N */
	      if (BE (pstr->mbs_allocated, 0))
		memmove (pstr->mbs, pstr->mbs + offset,
			 pstr->valid_len - offset);
	      pstr->valid_len -= offset;
	      pstr->valid_raw_len -= offset;
#if DEBUG
	      assert (pstr->valid_len > 0);
#endif
	    }
	}
      else
	{
#ifdef RE_ENABLE_I18N
	  /* No, skip all characters until IDX.  */
	  int prev_valid_len = pstr->valid_len;

	  if (BE (pstr->offsets_needed, 0))
	    {
	      pstr->len = pstr->raw_len - idx + offset;
	      pstr->stop = pstr->raw_stop - idx + offset;
	      pstr->offsets_needed = 0;
	    }
#endif
	  pstr->valid_len = 0;
#ifdef RE_ENABLE_I18N
	  if (pstr->mb_cur_max > 1)
	    {
	      int wcs_idx;
	      wint_t wc = WEOF;

	      if (pstr->is_utf8)
		{
		  const unsigned char *raw, *p, *end;

		  /* Special case UTF-8.  Multi-byte chars start with any
		     byte other than 0x80 - 0xbf.  */
		  raw = pstr->raw_mbs + pstr->raw_mbs_idx;
		  end = raw + (offset - pstr->mb_cur_max);
		  if (end < pstr->raw_mbs)
		    end = pstr->raw_mbs;
		  p = raw + offset - 1;
#ifdef _LIBC
		  /* We know the wchar_t encoding is UCS4, so for the simple
		     case, ASCII characters, skip the conversion step.  */
		  if (isascii (*p) && BE (pstr->trans == NULL, 1))
		    {
		      memset (&pstr->cur_state, '\0', sizeof (mbstate_t));
		      /* pstr->valid_len = 0; */
		      wc = (wchar_t) *p;
		    }
		  else
#endif
		    for (; p >= end; --p)
		      if ((*p & 0xc0) != 0x80)
			{
			  mbstate_t cur_state;
			  wchar_t wc2;
			  int mlen = raw + pstr->len - p;
			  unsigned char buf[6];
			  size_t mbclen;

			  if (BE (pstr->trans != NULL, 0))
			    {
			      int i = mlen < 6 ? mlen : 6;
			      while (--i >= 0)
				buf[i] = pstr->trans[p[i]];
			    }
			  /* XXX Don't use mbrtowc, we know which conversion
			     to use (UTF-8 -> UCS4).  */
			  memset (&cur_state, 0, sizeof (cur_state));
			  mbclen = __mbrtowc (&wc2, (const char *) p, mlen,
					      &cur_state);
			  if (raw + offset - p <= mbclen
			      && mbclen < (size_t) -2)
			    {
			      memset (&pstr->cur_state, '\0',
				      sizeof (mbstate_t));
			      pstr->valid_len = mbclen - (raw + offset - p);
			      wc = wc2;
			    }
			  break;
			}
		}

	      if (wc == WEOF)
		pstr->valid_len = re_string_skip_chars (pstr, idx, &wc) - idx;
	      if (wc == WEOF)
		pstr->tip_context
		  = re_string_context_at (pstr, prev_valid_len - 1, eflags);
	      else
		pstr->tip_context = ((BE (pstr->word_ops_used != 0, 0)
				      && IS_WIDE_WORD_CHAR (wc))
				     ? CONTEXT_WORD
				     : ((IS_WIDE_NEWLINE (wc)
					 && pstr->newline_anchor)
					? CONTEXT_NEWLINE : 0));
	      if (BE (pstr->valid_len, 0))
		{
		  for (wcs_idx = 0; wcs_idx < pstr->valid_len; ++wcs_idx)
		    pstr->wcs[wcs_idx] = WEOF;
		  if (pstr->mbs_allocated)
		    memset (pstr->mbs, 255, pstr->valid_len);
		}
	      pstr->valid_raw_len = pstr->valid_len;
	    }
	  else
#endif /* RE_ENABLE_I18N */
	    {
	      int c = pstr->raw_mbs[pstr->raw_mbs_idx + offset - 1];
	      pstr->valid_raw_len = 0;
	      if (pstr->trans)
		c = pstr->trans[c];
	      pstr->tip_context = (bitset_contain (pstr->word_char, c)
				   ? CONTEXT_WORD
				   : ((IS_NEWLINE (c) && pstr->newline_anchor)
				      ? CONTEXT_NEWLINE : 0));
	    }
	}
      if (!BE (pstr->mbs_allocated, 0))
	pstr->mbs += offset;
    }
  pstr->raw_mbs_idx = idx;
  pstr->len -= offset;
  pstr->stop -= offset;

  /* Then build the buffers.  */
#ifdef RE_ENABLE_I18N
  if (pstr->mb_cur_max > 1)
    {
      if (pstr->icase)
	{
	  reg_errcode_t ret = build_wcs_upper_buffer (pstr);
	  if (BE (ret != REG_NOERROR, 0))
	    return ret;
	}
      else
	build_wcs_buffer (pstr);
    }
  else
#endif /* RE_ENABLE_I18N */
    if (BE (pstr->mbs_allocated, 0))
      {
	if (pstr->icase)
	  build_upper_buffer (pstr);
	else if (pstr->trans != NULL)
	  re_string_translate_buffer (pstr);
      }
    else
      pstr->valid_len = pstr->len;

  pstr->cur_idx = 0;
  return REG_NOERROR;
}

static unsigned char
internal_function __attribute ((pure))
re_string_peek_byte_case (const re_string_t *pstr, int idx)
{
  int ch, off;

  /* Handle the common (easiest) cases first.  */
  if (BE (!pstr->mbs_allocated, 1))
    return re_string_peek_byte (pstr, idx);

#ifdef RE_ENABLE_I18N
  if (pstr->mb_cur_max > 1
      && ! re_string_is_single_byte_char (pstr, pstr->cur_idx + idx))
    return re_string_peek_byte (pstr, idx);
#endif

  off = pstr->cur_idx + idx;
#ifdef RE_ENABLE_I18N
  if (pstr->offsets_needed)
    off = pstr->offsets[off];
#endif

  ch = pstr->raw_mbs[pstr->raw_mbs_idx + off];

#ifdef RE_ENABLE_I18N
  /* Ensure that e.g. for tr_TR.UTF-8 BACKSLASH DOTLESS SMALL LETTER I
     this function returns CAPITAL LETTER I instead of first byte of
     DOTLESS SMALL LETTER I.  The latter would confuse the parser,
     since peek_byte_case doesn't advance cur_idx in any way.  */
  if (pstr->offsets_needed && !isascii (ch))
    return re_string_peek_byte (pstr, idx);
#endif

  return ch;
}

static unsigned char
internal_function __attribute ((pure))
re_string_fetch_byte_case (re_string_t *pstr)
{
  if (BE (!pstr->mbs_allocated, 1))
    return re_string_fetch_byte (pstr);

#ifdef RE_ENABLE_I18N
  if (pstr->offsets_needed)
    {
      int off, ch;

      /* For tr_TR.UTF-8 [[:islower:]] there is
	 [[: CAPITAL LETTER I WITH DOT lower:]] in mbs.  Skip
	 in that case the whole multi-byte character and return
	 the original letter.  On the other side, with
	 [[: DOTLESS SMALL LETTER I return [[:I, as doing
	 anything else would complicate things too much.  */

      if (!re_string_first_byte (pstr, pstr->cur_idx))
	return re_string_fetch_byte (pstr);

      off = pstr->offsets[pstr->cur_idx];
      ch = pstr->raw_mbs[pstr->raw_mbs_idx + off];

      if (! isascii (ch))
	return re_string_fetch_byte (pstr);

      re_string_skip_bytes (pstr,
			    re_string_char_size_at (pstr, pstr->cur_idx));
      return ch;
    }
#endif

  return pstr->raw_mbs[pstr->raw_mbs_idx + pstr->cur_idx++];
}

static void
internal_function
re_string_destruct (re_string_t *pstr)
{
#ifdef RE_ENABLE_I18N
  re_free (pstr->wcs);
  re_free (pstr->offsets);
#endif /* RE_ENABLE_I18N  */
  if (pstr->mbs_allocated)
    re_free (pstr->mbs);
}

/* Return the context at IDX in INPUT.  */

static unsigned int
internal_function
re_string_context_at (const re_string_t *input, int idx, int eflags)
{
  int c;
  if (BE (idx < 0, 0))
    /* In this case, we use the value stored in input->tip_context,
       since we can't know the character in input->mbs[-1] here.  */
    return input->tip_context;
  if (BE (idx == input->len, 0))
    return ((eflags & REG_NOTEOL) ? CONTEXT_ENDBUF
	    : CONTEXT_NEWLINE | CONTEXT_ENDBUF);
#ifdef RE_ENABLE_I18N
  if (input->mb_cur_max > 1)
    {
      wint_t wc;
      int wc_idx = idx;
      while(input->wcs[wc_idx] == WEOF)
	{
#ifdef DEBUG
	  /* It must not happen.  */
	  assert (wc_idx >= 0);
#endif
	  --wc_idx;
	  if (wc_idx < 0)
	    return input->tip_context;
	}
      wc = input->wcs[wc_idx];
      if (BE (input->word_ops_used != 0, 0) && IS_WIDE_WORD_CHAR (wc))
	return CONTEXT_WORD;
      return (IS_WIDE_NEWLINE (wc) && input->newline_anchor
	      ? CONTEXT_NEWLINE : 0);
    }
  else
#endif
    {
      c = re_string_byte_at (input, idx);
      if (bitset_contain (input->word_char, c))
	return CONTEXT_WORD;
      return IS_NEWLINE (c) && input->newline_anchor ? CONTEXT_NEWLINE : 0;
    }
}

/* Functions for set operation.  */

static reg_errcode_t
internal_function
re_node_set_alloc (re_node_set *set, int size)
{
  /*
   * ADR: valgrind says size can be 0, which then doesn't
   * free the block of size 0.  Harumph. This seems
   * to work ok, though.
   */
  if (size == 0)
    {
       memset(set, 0, sizeof(*set));
       return REG_NOERROR;
    }
  set->alloc = size;
  set->nelem = 0;
  set->elems = re_malloc (int, size);
  if (BE (set->elems == NULL, 0))
    return REG_ESPACE;
  return REG_NOERROR;
}

static reg_errcode_t
internal_function
re_node_set_init_1 (re_node_set *set, int elem)
{
  set->alloc = 1;
  set->nelem = 1;
  set->elems = re_malloc (int, 1);
  if (BE (set->elems == NULL, 0))
    {
      set->alloc = set->nelem = 0;
      return REG_ESPACE;
    }
  set->elems[0] = elem;
  return REG_NOERROR;
}

static reg_errcode_t
internal_function
re_node_set_init_2 (re_node_set *set, int elem1, int elem2)
{
  set->alloc = 2;
  set->elems = re_malloc (int, 2);
  if (BE (set->elems == NULL, 0))
    return REG_ESPACE;
  if (elem1 == elem2)
    {
      set->nelem = 1;
      set->elems[0] = elem1;
    }
  else
    {
      set->nelem = 2;
      if (elem1 < elem2)
	{
	  set->elems[0] = elem1;
	  set->elems[1] = elem2;
	}
      else
	{
	  set->elems[0] = elem2;
	  set->elems[1] = elem1;
	}
    }
  return REG_NOERROR;
}

static reg_errcode_t
internal_function
re_node_set_init_copy (re_node_set *dest, const re_node_set *src)
{
  dest->nelem = src->nelem;
  if (src->nelem > 0)
    {
      dest->alloc = dest->nelem;
      dest->elems = re_malloc (int, dest->alloc);
      if (BE (dest->elems == NULL, 0))
	{
	  dest->alloc = dest->nelem = 0;
	  return REG_ESPACE;
	}
      memcpy (dest->elems, src->elems, src->nelem * sizeof (int));
    }
  else
    re_node_set_init_empty (dest);
  return REG_NOERROR;
}

/* Calculate the intersection of the sets SRC1 and SRC2. And merge it to
   DEST. Return value indicate the error code or REG_NOERROR if succeeded.
   Note: We assume dest->elems is NULL, when dest->alloc is 0.  */

static reg_errcode_t
internal_function
re_node_set_add_intersect (re_node_set *dest, const re_node_set *src1,
			   const re_node_set *src2)
{
  int i1, i2, is, id, delta, sbase;
  if (src1->nelem == 0 || src2->nelem == 0)
    return REG_NOERROR;

  /* We need dest->nelem + 2 * elems_in_intersection; this is a
     conservative estimate.  */
  if (src1->nelem + src2->nelem + dest->nelem > dest->alloc)
    {
      int new_alloc = src1->nelem + src2->nelem + dest->alloc;
      int *new_elems = re_realloc (dest->elems, int, new_alloc);
      if (BE (new_elems == NULL, 0))
	return REG_ESPACE;
      dest->elems = new_elems;
      dest->alloc = new_alloc;
    }

  /* Find the items in the intersection of SRC1 and SRC2, and copy
     into the top of DEST those that are not already in DEST itself.  */
  sbase = dest->nelem + src1->nelem + src2->nelem;
  i1 = src1->nelem - 1;
  i2 = src2->nelem - 1;
  id = dest->nelem - 1;
  for (;;)
    {
      if (src1->elems[i1] == src2->elems[i2])
	{
	  /* Try to find the item in DEST.  Maybe we could binary search?  */
	  while (id >= 0 && dest->elems[id] > src1->elems[i1])
	    --id;

	  if (id < 0 || dest->elems[id] != src1->elems[i1])
	    dest->elems[--sbase] = src1->elems[i1];

	  if (--i1 < 0 || --i2 < 0)
	    break;
	}

      /* Lower the highest of the two items.  */
      else if (src1->elems[i1] < src2->elems[i2])
	{
	  if (--i2 < 0)
	    break;
	}
      else
	{
	  if (--i1 < 0)
	    break;
	}
    }

  id = dest->nelem - 1;
  is = dest->nelem + src1->nelem + src2->nelem - 1;
  delta = is - sbase + 1;

  /* Now copy.  When DELTA becomes zero, the remaining
     DEST elements are already in place; this is more or
     less the same loop that is in re_node_set_merge.  */
  dest->nelem += delta;
  if (delta > 0 && id >= 0)
    for (;;)
      {
	if (dest->elems[is] > dest->elems[id])
	  {
	    /* Copy from the top.  */
	    dest->elems[id + delta--] = dest->elems[is--];
	    if (delta == 0)
	      break;
	  }
	else
	  {
	    /* Slide from the bottom.  */
	    dest->elems[id + delta] = dest->elems[id];
	    if (--id < 0)
	      break;
	  }
      }

  /* Copy remaining SRC elements.  */
  memcpy (dest->elems, dest->elems + sbase, delta * sizeof (int));

  return REG_NOERROR;
}

/* Calculate the union set of the sets SRC1 and SRC2. And store it to
   DEST. Return value indicate the error code or REG_NOERROR if succeeded.  */

static reg_errcode_t
internal_function
re_node_set_init_union (re_node_set *dest, const re_node_set *src1,
			const re_node_set *src2)
{
  int i1, i2, id;
  if (src1 != NULL && src1->nelem > 0 && src2 != NULL && src2->nelem > 0)
    {
      dest->alloc = src1->nelem + src2->nelem;
      dest->elems = re_malloc (int, dest->alloc);
      if (BE (dest->elems == NULL, 0))
	return REG_ESPACE;
    }
  else
    {
      if (src1 != NULL && src1->nelem > 0)
	return re_node_set_init_copy (dest, src1);
      else if (src2 != NULL && src2->nelem > 0)
	return re_node_set_init_copy (dest, src2);
      else
	re_node_set_init_empty (dest);
      return REG_NOERROR;
    }
  for (i1 = i2 = id = 0 ; i1 < src1->nelem && i2 < src2->nelem ;)
    {
      if (src1->elems[i1] > src2->elems[i2])
	{
	  dest->elems[id++] = src2->elems[i2++];
	  continue;
	}
      if (src1->elems[i1] == src2->elems[i2])
	++i2;
      dest->elems[id++] = src1->elems[i1++];
    }
  if (i1 < src1->nelem)
    {
      memcpy (dest->elems + id, src1->elems + i1,
	     (src1->nelem - i1) * sizeof (int));
      id += src1->nelem - i1;
    }
  else if (i2 < src2->nelem)
    {
      memcpy (dest->elems + id, src2->elems + i2,
	     (src2->nelem - i2) * sizeof (int));
      id += src2->nelem - i2;
    }
  dest->nelem = id;
  return REG_NOERROR;
}

/* Calculate the union set of the sets DEST and SRC. And store it to
   DEST. Return value indicate the error code or REG_NOERROR if succeeded.  */

static reg_errcode_t
internal_function
re_node_set_merge (re_node_set *dest, const re_node_set *src)
{
  int is, id, sbase, delta;
  if (src == NULL || src->nelem == 0)
    return REG_NOERROR;
  if (dest->alloc < 2 * src->nelem + dest->nelem)
    {
      int new_alloc = 2 * (src->nelem + dest->alloc);
      int *new_buffer = re_realloc (dest->elems, int, new_alloc);
      if (BE (new_buffer == NULL, 0))
	return REG_ESPACE;
      dest->elems = new_buffer;
      dest->alloc = new_alloc;
    }

  if (BE (dest->nelem == 0, 0))
    {
      dest->nelem = src->nelem;
      memcpy (dest->elems, src->elems, src->nelem * sizeof (int));
      return REG_NOERROR;
    }

  /* Copy into the top of DEST the items of SRC that are not
     found in DEST.  Maybe we could binary search in DEST?  */
  for (sbase = dest->nelem + 2 * src->nelem,
       is = src->nelem - 1, id = dest->nelem - 1; is >= 0 && id >= 0; )
    {
      if (dest->elems[id] == src->elems[is])
	is--, id--;
      else if (dest->elems[id] < src->elems[is])
	dest->elems[--sbase] = src->elems[is--];
      else /* if (dest->elems[id] > src->elems[is]) */
	--id;
    }

  if (is >= 0)
    {
      /* If DEST is exhausted, the remaining items of SRC must be unique.  */
      sbase -= is + 1;
      memcpy (dest->elems + sbase, src->elems, (is + 1) * sizeof (int));
    }

  id = dest->nelem - 1;
  is = dest->nelem + 2 * src->nelem - 1;
  delta = is - sbase + 1;
  if (delta == 0)
    return REG_NOERROR;

  /* Now copy.  When DELTA becomes zero, the remaining
     DEST elements are already in place.  */
  dest->nelem += delta;
  for (;;)
    {
      if (dest->elems[is] > dest->elems[id])
	{
	  /* Copy from the top.  */
	  dest->elems[id + delta--] = dest->elems[is--];
	  if (delta == 0)
	    break;
	}
      else
	{
	  /* Slide from the bottom.  */
	  dest->elems[id + delta] = dest->elems[id];
	  if (--id < 0)
	    {
	      /* Copy remaining SRC elements.  */
	      memcpy (dest->elems, dest->elems + sbase,
		      delta * sizeof (int));
	      break;
	    }
	}
    }

  return REG_NOERROR;
}

/* Insert the new element ELEM to the re_node_set* SET.
   SET should not already have ELEM.
   return -1 if an error is occured, return 1 otherwise.  */

static int
internal_function
re_node_set_insert (re_node_set *set, int elem)
{
  int idx;
  /* In case the set is empty.  */
  if (set->alloc == 0)
    {
      if (BE (re_node_set_init_1 (set, elem) == REG_NOERROR, 1))
	return 1;
      else
	return -1;
    }

  if (BE (set->nelem, 0) == 0)
    {
      /* We already guaranteed above that set->alloc != 0.  */
      set->elems[0] = elem;
      ++set->nelem;
      return 1;
    }

  /* Realloc if we need.  */
  if (set->alloc == set->nelem)
    {
      int *new_elems;
      set->alloc = set->alloc * 2;
      new_elems = re_realloc (set->elems, int, set->alloc);
      if (BE (new_elems == NULL, 0))
	return -1;
      set->elems = new_elems;
    }

  /* Move the elements which follows the new element.  Test the
     first element separately to skip a check in the inner loop.  */
  if (elem < set->elems[0])
    {
      idx = 0;
      for (idx = set->nelem; idx > 0; idx--)
	set->elems[idx] = set->elems[idx - 1];
    }
  else
    {
      for (idx = set->nelem; set->elems[idx - 1] > elem; idx--)
	set->elems[idx] = set->elems[idx - 1];
    }

  /* Insert the new element.  */
  set->elems[idx] = elem;
  ++set->nelem;
  return 1;
}

/* Insert the new element ELEM to the re_node_set* SET.
   SET should not already have any element greater than or equal to ELEM.
   Return -1 if an error is occured, return 1 otherwise.  */

static int
internal_function
re_node_set_insert_last (re_node_set *set, int elem)
{
  /* Realloc if we need.  */
  if (set->alloc == set->nelem)
    {
      int *new_elems;
      set->alloc = (set->alloc + 1) * 2;
      new_elems = re_realloc (set->elems, int, set->alloc);
      if (BE (new_elems == NULL, 0))
	return -1;
      set->elems = new_elems;
    }

  /* Insert the new element.  */
  set->elems[set->nelem++] = elem;
  return 1;
}

/* Compare two node sets SET1 and SET2.
   return 1 if SET1 and SET2 are equivalent, return 0 otherwise.  */

static int
internal_function __attribute ((pure))
re_node_set_compare (const re_node_set *set1, const re_node_set *set2)
{
  int i;
  if (set1 == NULL || set2 == NULL || set1->nelem != set2->nelem)
    return 0;
  for (i = set1->nelem ; --i >= 0 ; )
    if (set1->elems[i] != set2->elems[i])
      return 0;
  return 1;
}

/* Return (idx + 1) if SET contains the element ELEM, return 0 otherwise.  */

static int
internal_function __attribute ((pure))
re_node_set_contains (const re_node_set *set, int elem)
{
  unsigned int idx, right, mid;
  if (set->nelem <= 0)
    return 0;

  /* Binary search the element.  */
  idx = 0;
  right = set->nelem - 1;
  while (idx < right)
    {
      mid = (idx + right) / 2;
      if (set->elems[mid] < elem)
	idx = mid + 1;
      else
	right = mid;
    }
  return set->elems[idx] == elem ? idx + 1 : 0;
}

static void
internal_function
re_node_set_remove_at (re_node_set *set, int idx)
{
  if (idx < 0 || idx >= set->nelem)
    return;
  --set->nelem;
  for (; idx < set->nelem; idx++)
    set->elems[idx] = set->elems[idx + 1];
}


/* Add the token TOKEN to dfa->nodes, and return the index of the token.
   Or return -1, if an error will be occured.  */

static int
internal_function
re_dfa_add_node (re_dfa_t *dfa, re_token_t token)
{
  if (BE (dfa->nodes_len >= dfa->nodes_alloc, 0))
    {
      size_t new_nodes_alloc = dfa->nodes_alloc * 2;
      int *new_nexts, *new_indices;
      re_node_set *new_edests, *new_eclosures;
      re_token_t *new_nodes;

      /* Avoid overflows in realloc.  */
      const size_t max_object_size = MAX (sizeof (re_token_t),
					  MAX (sizeof (re_node_set),
					       sizeof (int)));
      if (BE (SIZE_MAX / max_object_size < new_nodes_alloc, 0))
	return -1;

      new_nodes = re_realloc (dfa->nodes, re_token_t, new_nodes_alloc);
      if (BE (new_nodes == NULL, 0))
	return -1;
      dfa->nodes = new_nodes;
      new_nexts = re_realloc (dfa->nexts, int, new_nodes_alloc);
      new_indices = re_realloc (dfa->org_indices, int, new_nodes_alloc);
      new_edests = re_realloc (dfa->edests, re_node_set, new_nodes_alloc);
      new_eclosures = re_realloc (dfa->eclosures, re_node_set, new_nodes_alloc);
      if (BE (new_nexts == NULL || new_indices == NULL
	      || new_edests == NULL || new_eclosures == NULL, 0))
	return -1;
      dfa->nexts = new_nexts;
      dfa->org_indices = new_indices;
      dfa->edests = new_edests;
      dfa->eclosures = new_eclosures;
      dfa->nodes_alloc = new_nodes_alloc;
    }
  dfa->nodes[dfa->nodes_len] = token;
  dfa->nodes[dfa->nodes_len].constraint = 0;
#ifdef RE_ENABLE_I18N
  dfa->nodes[dfa->nodes_len].accept_mb =
    (token.type == OP_PERIOD && dfa->mb_cur_max > 1) || token.type == COMPLEX_BRACKET;
#endif
  dfa->nexts[dfa->nodes_len] = -1;
  re_node_set_init_empty (dfa->edests + dfa->nodes_len);
  re_node_set_init_empty (dfa->eclosures + dfa->nodes_len);
  return dfa->nodes_len++;
}

static inline unsigned int
internal_function
calc_state_hash (const re_node_set *nodes, unsigned int context)
{
  unsigned int hash = nodes->nelem + context;
  int i;
  for (i = 0 ; i < nodes->nelem ; i++)
    hash += nodes->elems[i];
  return hash;
}

/* Search for the state whose node_set is equivalent to NODES.
   Return the pointer to the state, if we found it in the DFA.
   Otherwise create the new one and return it.  In case of an error
   return NULL and set the error code in ERR.
   Note: - We assume NULL as the invalid state, then it is possible that
	   return value is NULL and ERR is REG_NOERROR.
	 - We never return non-NULL value in case of any errors, it is for
	   optimization.  */

static re_dfastate_t *
internal_function
re_acquire_state (reg_errcode_t *err, const re_dfa_t *dfa,
		  const re_node_set *nodes)
{
  unsigned int hash;
  re_dfastate_t *new_state;
  struct re_state_table_entry *spot;
  int i;
  if (BE (nodes->nelem == 0, 0))
    {
      *err = REG_NOERROR;
      return NULL;
    }
  hash = calc_state_hash (nodes, 0);
  spot = dfa->state_table + (hash & dfa->state_hash_mask);

  for (i = 0 ; i < spot->num ; i++)
    {
      re_dfastate_t *state = spot->array[i];
      if (hash != state->hash)
	continue;
      if (re_node_set_compare (&state->nodes, nodes))
	return state;
    }

  /* There are no appropriate state in the dfa, create the new one.  */
  new_state = create_ci_newstate (dfa, nodes, hash);
  if (BE (new_state == NULL, 0))
    *err = REG_ESPACE;

  return new_state;
}

/* Search for the state whose node_set is equivalent to NODES and
   whose context is equivalent to CONTEXT.
   Return the pointer to the state, if we found it in the DFA.
   Otherwise create the new one and return it.  In case of an error
   return NULL and set the error code in ERR.
   Note: - We assume NULL as the invalid state, then it is possible that
	   return value is NULL and ERR is REG_NOERROR.
	 - We never return non-NULL value in case of any errors, it is for
	   optimization.  */

static re_dfastate_t *
internal_function
re_acquire_state_context (reg_errcode_t *err, const re_dfa_t *dfa,
			  const re_node_set *nodes, unsigned int context)
{
  unsigned int hash;
  re_dfastate_t *new_state;
  struct re_state_table_entry *spot;
  int i;
  if (nodes->nelem == 0)
    {
      *err = REG_NOERROR;
      return NULL;
    }
  hash = calc_state_hash (nodes, context);
  spot = dfa->state_table + (hash & dfa->state_hash_mask);

  for (i = 0 ; i < spot->num ; i++)
    {
      re_dfastate_t *state = spot->array[i];
      if (state->hash == hash
	  && state->context == context
	  && re_node_set_compare (state->entrance_nodes, nodes))
	return state;
    }
  /* There are no appropriate state in `dfa', create the new one.  */
  new_state = create_cd_newstate (dfa, nodes, context, hash);
  if (BE (new_state == NULL, 0))
    *err = REG_ESPACE;

  return new_state;
}

/* Finish initialization of the new state NEWSTATE, and using its hash value
   HASH put in the appropriate bucket of DFA's state table.  Return value
   indicates the error code if failed.  */

static reg_errcode_t
register_state (const re_dfa_t *dfa, re_dfastate_t *newstate,
		unsigned int hash)
{
  struct re_state_table_entry *spot;
  reg_errcode_t err;
  int i;

  newstate->hash = hash;
  err = re_node_set_alloc (&newstate->non_eps_nodes, newstate->nodes.nelem);
  if (BE (err != REG_NOERROR, 0))
    return REG_ESPACE;
  for (i = 0; i < newstate->nodes.nelem; i++)
    {
      int elem = newstate->nodes.elems[i];
      if (!IS_EPSILON_NODE (dfa->nodes[elem].type))
	if (re_node_set_insert_last (&newstate->non_eps_nodes, elem) < 0)
	  return REG_ESPACE;
    }

  spot = dfa->state_table + (hash & dfa->state_hash_mask);
  if (BE (spot->alloc <= spot->num, 0))
    {
      int new_alloc = 2 * spot->num + 2;
      re_dfastate_t **new_array = re_realloc (spot->array, re_dfastate_t *,
					      new_alloc);
      if (BE (new_array == NULL, 0))
	return REG_ESPACE;
      spot->array = new_array;
      spot->alloc = new_alloc;
    }
  spot->array[spot->num++] = newstate;
  return REG_NOERROR;
}

static void
free_state (re_dfastate_t *state)
{
  re_node_set_free (&state->non_eps_nodes);
  re_node_set_free (&state->inveclosure);
  if (state->entrance_nodes != &state->nodes)
    {
      re_node_set_free (state->entrance_nodes);
      re_free (state->entrance_nodes);
    }
  re_node_set_free (&state->nodes);
  re_free (state->word_trtable);
  re_free (state->trtable);
  re_free (state);
}

/* Create the new state which is independ of contexts.
   Return the new state if succeeded, otherwise return NULL.  */

static re_dfastate_t *
internal_function
create_ci_newstate (const re_dfa_t *dfa, const re_node_set *nodes,
		    unsigned int hash)
{
  int i;
  reg_errcode_t err;
  re_dfastate_t *newstate;

  newstate = (re_dfastate_t *) calloc (sizeof (re_dfastate_t), 1);
  if (BE (newstate == NULL, 0))
    return NULL;
  err = re_node_set_init_copy (&newstate->nodes, nodes);
  if (BE (err != REG_NOERROR, 0))
    {
      re_free (newstate);
      return NULL;
    }

  newstate->entrance_nodes = &newstate->nodes;
  for (i = 0 ; i < nodes->nelem ; i++)
    {
      re_token_t *node = dfa->nodes + nodes->elems[i];
      re_token_type_t type = node->type;
      if (type == CHARACTER && !node->constraint)
	continue;
#ifdef RE_ENABLE_I18N
      newstate->accept_mb |= node->accept_mb;
#endif /* RE_ENABLE_I18N */

      /* If the state has the halt node, the state is a halt state.  */
      if (type == END_OF_RE)
	newstate->halt = 1;
      else if (type == OP_BACK_REF)
	newstate->has_backref = 1;
      else if (type == ANCHOR || node->constraint)
	newstate->has_constraint = 1;
    }
  err = register_state (dfa, newstate, hash);
  if (BE (err != REG_NOERROR, 0))
    {
      free_state (newstate);
      newstate = NULL;
    }
  return newstate;
}

/* Create the new state which is depend on the context CONTEXT.
   Return the new state if succeeded, otherwise return NULL.  */

static re_dfastate_t *
internal_function
create_cd_newstate (const re_dfa_t *dfa, const re_node_set *nodes,
		    unsigned int context, unsigned int hash)
{
  int i, nctx_nodes = 0;
  reg_errcode_t err;
  re_dfastate_t *newstate;

  newstate = (re_dfastate_t *) calloc (sizeof (re_dfastate_t), 1);
  if (BE (newstate == NULL, 0))
    return NULL;
  err = re_node_set_init_copy (&newstate->nodes, nodes);
  if (BE (err != REG_NOERROR, 0))
    {
      re_free (newstate);
      return NULL;
    }

  newstate->context = context;
  newstate->entrance_nodes = &newstate->nodes;

  for (i = 0 ; i < nodes->nelem ; i++)
    {
      re_token_t *node = dfa->nodes + nodes->elems[i];
      re_token_type_t type = node->type;
      unsigned int constraint = node->constraint;

      if (type == CHARACTER && !constraint)
	continue;
#ifdef RE_ENABLE_I18N
      newstate->accept_mb |= node->accept_mb;
#endif /* RE_ENABLE_I18N */

      /* If the state has the halt node, the state is a halt state.  */
      if (type == END_OF_RE)
	newstate->halt = 1;
      else if (type == OP_BACK_REF)
	newstate->has_backref = 1;

      if (constraint)
	{
	  if (newstate->entrance_nodes == &newstate->nodes)
	    {
	      newstate->entrance_nodes = re_malloc (re_node_set, 1);
	      if (BE (newstate->entrance_nodes == NULL, 0))
		{
		  free_state (newstate);
		  return NULL;
		}
	      if (re_node_set_init_copy (newstate->entrance_nodes, nodes)
		  != REG_NOERROR)
		return NULL;
	      nctx_nodes = 0;
	      newstate->has_constraint = 1;
	    }

	  if (NOT_SATISFY_PREV_CONSTRAINT (constraint,context))
	    {
	      re_node_set_remove_at (&newstate->nodes, i - nctx_nodes);
	      ++nctx_nodes;
	    }
	}
    }
  err = register_state (dfa, newstate, hash);
  if (BE (err != REG_NOERROR, 0))
    {
      free_state (newstate);
      newstate = NULL;
    }
  return  newstate;
}

#ifdef GAWK
# define bool int

# ifndef true
#  define true (1)
# endif

# ifndef false
#  define false (0)
# endif
#endif

/* Binary backward compatibility.  */
#if _LIBC
# include <shlib-compat.h>
# if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_3)
link_warning (re_max_failures, "the 're_max_failures' variable is obsolete and will go away.")
int re_max_failures = 2000;
# endif
#endif

static reg_errcode_t re_compile_internal (regex_t *preg, const char * pattern,
					  size_t length, reg_syntax_t syntax);
static void re_compile_fastmap_iter (regex_t *bufp,
				     const re_dfastate_t *init_state,
				     char *fastmap);
static reg_errcode_t init_dfa (re_dfa_t *dfa, size_t pat_len);
#ifdef RE_ENABLE_I18N
static void free_charset (re_charset_t *cset);
#endif /* RE_ENABLE_I18N */
static void free_workarea_compile (regex_t *preg);
static reg_errcode_t create_initial_state (re_dfa_t *dfa);
#ifdef RE_ENABLE_I18N
static void optimize_utf8 (re_dfa_t *dfa);
#endif
static reg_errcode_t analyze (regex_t *preg);
static reg_errcode_t preorder (bin_tree_t *root,
			       reg_errcode_t (fn (void *, bin_tree_t *)),
			       void *extra);
static reg_errcode_t postorder (bin_tree_t *root,
				reg_errcode_t (fn (void *, bin_tree_t *)),
				void *extra);
static reg_errcode_t optimize_subexps (void *extra, bin_tree_t *node);
static reg_errcode_t lower_subexps (void *extra, bin_tree_t *node);
static bin_tree_t *lower_subexp (reg_errcode_t *err, regex_t *preg,
				 bin_tree_t *node);
static reg_errcode_t calc_first (void *extra, bin_tree_t *node);
static reg_errcode_t calc_next (void *extra, bin_tree_t *node);
static reg_errcode_t link_nfa_nodes (void *extra, bin_tree_t *node);
static int duplicate_node (re_dfa_t *dfa, int org_idx, unsigned int constraint);
static int search_duplicated_node (const re_dfa_t *dfa, int org_node,
				   unsigned int constraint);
static reg_errcode_t calc_eclosure (re_dfa_t *dfa);
static reg_errcode_t calc_eclosure_iter (re_node_set *new_set, re_dfa_t *dfa,
					 int node, int root);
static reg_errcode_t calc_inveclosure (re_dfa_t *dfa);
static int fetch_number (re_string_t *input, re_token_t *token,
			 reg_syntax_t syntax);
static int peek_token (re_token_t *token, re_string_t *input,
			reg_syntax_t syntax) internal_function;
static bin_tree_t *parse (re_string_t *regexp, regex_t *preg,
			  reg_syntax_t syntax, reg_errcode_t *err);
static bin_tree_t *parse_reg_exp (re_string_t *regexp, regex_t *preg,
				  re_token_t *token, reg_syntax_t syntax,
				  int nest, reg_errcode_t *err);
static bin_tree_t *parse_branch (re_string_t *regexp, regex_t *preg,
				 re_token_t *token, reg_syntax_t syntax,
				 int nest, reg_errcode_t *err);
static bin_tree_t *parse_expression (re_string_t *regexp, regex_t *preg,
				     re_token_t *token, reg_syntax_t syntax,
				     int nest, reg_errcode_t *err);
static bin_tree_t *parse_sub_exp (re_string_t *regexp, regex_t *preg,
				  re_token_t *token, reg_syntax_t syntax,
				  int nest, reg_errcode_t *err);
static bin_tree_t *parse_dup_op (bin_tree_t *dup_elem, re_string_t *regexp,
				 re_dfa_t *dfa, re_token_t *token,
				 reg_syntax_t syntax, reg_errcode_t *err);
static bin_tree_t *parse_bracket_exp (re_string_t *regexp, re_dfa_t *dfa,
				      re_token_t *token, reg_syntax_t syntax,
				      reg_errcode_t *err);
static reg_errcode_t parse_bracket_element (bracket_elem_t *elem,
					    re_string_t *regexp,
					    re_token_t *token, int token_len,
					    re_dfa_t *dfa,
					    reg_syntax_t syntax,
					    int accept_hyphen);
static reg_errcode_t parse_bracket_symbol (bracket_elem_t *elem,
					  re_string_t *regexp,
					  re_token_t *token);
#ifdef RE_ENABLE_I18N
static reg_errcode_t build_equiv_class (bitset_t sbcset,
					re_charset_t *mbcset,
					int *equiv_class_alloc,
					const unsigned char *name);
static reg_errcode_t build_charclass (RE_TRANSLATE_TYPE trans,
				      bitset_t sbcset,
				      re_charset_t *mbcset,
				      int *char_class_alloc,
				      const char *class_name,
				      reg_syntax_t syntax);
#else  /* not RE_ENABLE_I18N */
static reg_errcode_t build_equiv_class (bitset_t sbcset,
					const unsigned char *name);
static reg_errcode_t build_charclass (RE_TRANSLATE_TYPE trans,
				      bitset_t sbcset,
				      const char *class_name,
				      reg_syntax_t syntax);
#endif /* not RE_ENABLE_I18N */
static bin_tree_t *build_charclass_op (re_dfa_t *dfa,
				       RE_TRANSLATE_TYPE trans,
				       const char *class_name,
				       const char *extra,
				       int non_match, reg_errcode_t *err);
static bin_tree_t *create_tree (re_dfa_t *dfa,
				bin_tree_t *left, bin_tree_t *right,
				re_token_type_t type);
static bin_tree_t *create_token_tree (re_dfa_t *dfa,
				      bin_tree_t *left, bin_tree_t *right,
				      const re_token_t *token);
static bin_tree_t *duplicate_tree (const bin_tree_t *src, re_dfa_t *dfa);
static void free_token (re_token_t *node);
static reg_errcode_t free_tree (void *extra, bin_tree_t *node);
static reg_errcode_t mark_opt_subexp (void *extra, bin_tree_t *node);

/* This table gives an error message for each of the error codes listed
   in regex.h.  Obviously the order here has to be same as there.
   POSIX doesn't require that we do anything for REG_NOERROR,
   but why not be nice?  */

const char __re_error_msgid[] attribute_hidden =
  {
#define REG_NOERROR_IDX	0
    gettext_noop ("Success")	/* REG_NOERROR */
    "\0"
#define REG_NOMATCH_IDX (REG_NOERROR_IDX + sizeof "Success")
    gettext_noop ("No match")	/* REG_NOMATCH */
    "\0"
#define REG_BADPAT_IDX	(REG_NOMATCH_IDX + sizeof "No match")
    gettext_noop ("Invalid regular expression") /* REG_BADPAT */
    "\0"
#define REG_ECOLLATE_IDX (REG_BADPAT_IDX + sizeof "Invalid regular expression")
    gettext_noop ("Invalid collation character") /* REG_ECOLLATE */
    "\0"
#define REG_ECTYPE_IDX	(REG_ECOLLATE_IDX + sizeof "Invalid collation character")
    gettext_noop ("Invalid character class name") /* REG_ECTYPE */
    "\0"
#define REG_EESCAPE_IDX	(REG_ECTYPE_IDX + sizeof "Invalid character class name")
    gettext_noop ("Trailing backslash") /* REG_EESCAPE */
    "\0"
#define REG_ESUBREG_IDX	(REG_EESCAPE_IDX + sizeof "Trailing backslash")
    gettext_noop ("Invalid back reference") /* REG_ESUBREG */
    "\0"
#define REG_EBRACK_IDX	(REG_ESUBREG_IDX + sizeof "Invalid back reference")
    gettext_noop ("Unmatched [ or [^")	/* REG_EBRACK */
    "\0"
#define REG_EPAREN_IDX	(REG_EBRACK_IDX + sizeof "Unmatched [ or [^")
    gettext_noop ("Unmatched ( or \\(") /* REG_EPAREN */
    "\0"
#define REG_EBRACE_IDX	(REG_EPAREN_IDX + sizeof "Unmatched ( or \\(")
    gettext_noop ("Unmatched \\{") /* REG_EBRACE */
    "\0"
#define REG_BADBR_IDX	(REG_EBRACE_IDX + sizeof "Unmatched \\{")
    gettext_noop ("Invalid content of \\{\\}") /* REG_BADBR */
    "\0"
#define REG_ERANGE_IDX	(REG_BADBR_IDX + sizeof "Invalid content of \\{\\}")
    gettext_noop ("Invalid range end")	/* REG_ERANGE */
    "\0"
#define REG_ESPACE_IDX	(REG_ERANGE_IDX + sizeof "Invalid range end")
    gettext_noop ("Memory exhausted") /* REG_ESPACE */
    "\0"
#define REG_BADRPT_IDX	(REG_ESPACE_IDX + sizeof "Memory exhausted")
    gettext_noop ("Invalid preceding regular expression") /* REG_BADRPT */
    "\0"
#define REG_EEND_IDX	(REG_BADRPT_IDX + sizeof "Invalid preceding regular expression")
    gettext_noop ("Premature end of regular expression") /* REG_EEND */
    "\0"
#define REG_ESIZE_IDX	(REG_EEND_IDX + sizeof "Premature end of regular expression")
    gettext_noop ("Regular expression too big") /* REG_ESIZE */
    "\0"
#define REG_ERPAREN_IDX	(REG_ESIZE_IDX + sizeof "Regular expression too big")
    gettext_noop ("Unmatched ) or \\)") /* REG_ERPAREN */
  };

const size_t __re_error_msgid_idx[] attribute_hidden =
  {
    REG_NOERROR_IDX,
    REG_NOMATCH_IDX,
    REG_BADPAT_IDX,
    REG_ECOLLATE_IDX,
    REG_ECTYPE_IDX,
    REG_EESCAPE_IDX,
    REG_ESUBREG_IDX,
    REG_EBRACK_IDX,
    REG_EPAREN_IDX,
    REG_EBRACE_IDX,
    REG_BADBR_IDX,
    REG_ERANGE_IDX,
    REG_ESPACE_IDX,
    REG_BADRPT_IDX,
    REG_EEND_IDX,
    REG_ESIZE_IDX,
    REG_ERPAREN_IDX
  };

/* Entry points for GNU code.  */


#ifdef ZOS_USS

/* For ZOS USS we must define btowc */

wchar_t 
btowc (int c)
{
   wchar_t wtmp[2];
   char tmp[2];

   tmp[0] = c;
   tmp[1] = 0;

   mbtowc (wtmp, tmp, 1);
   return wtmp[0];
}
#endif

/* re_compile_pattern is the GNU regular expression compiler: it
   compiles PATTERN (of length LENGTH) and puts the result in BUFP.
   Returns 0 if the pattern was valid, otherwise an error string.

   Assumes the `allocated' (and perhaps `buffer') and `translate' fields
   are set in BUFP on entry.  */

const char *
re_compile_pattern (const char *pattern,
		    size_t length,
		    struct re_pattern_buffer *bufp)
{
  reg_errcode_t ret;

  /* And GNU code determines whether or not to get register information
     by passing null for the REGS argument to re_match, etc., not by
     setting no_sub, unless RE_NO_SUB is set.  */
  bufp->no_sub = !!(re_syntax_options & RE_NO_SUB);

  /* Match anchors at newline.  */
  bufp->newline_anchor = 1;

  ret = re_compile_internal (bufp, pattern, length, re_syntax_options);

  if (!ret)
    return NULL;
  return gettext (__re_error_msgid + __re_error_msgid_idx[(int) ret]);
}
#ifdef _LIBC
weak_alias (__re_compile_pattern, re_compile_pattern)
#endif

/* Set by `re_set_syntax' to the current regexp syntax to recognize.  Can
   also be assigned to arbitrarily: each pattern buffer stores its own
   syntax, so it can be changed between regex compilations.  */
/* This has no initializer because initialized variables in Emacs
   become read-only after dumping.  */
reg_syntax_t re_syntax_options;


/* Specify the precise syntax of regexps for compilation.  This provides
   for compatibility for various utilities which historically have
   different, incompatible syntaxes.

   The argument SYNTAX is a bit mask comprised of the various bits
   defined in regex.h.  We return the old syntax.  */

reg_syntax_t
re_set_syntax (reg_syntax_t syntax)
{
  reg_syntax_t ret = re_syntax_options;

  re_syntax_options = syntax;
  return ret;
}
#ifdef _LIBC
weak_alias (__re_set_syntax, re_set_syntax)
#endif

int
re_compile_fastmap (struct re_pattern_buffer *bufp)
{
  re_dfa_t *dfa = (re_dfa_t *) bufp->buffer;
  char *fastmap = bufp->fastmap;

  memset (fastmap, '\0', sizeof (char) * SBC_MAX);
  re_compile_fastmap_iter (bufp, dfa->init_state, fastmap);
  if (dfa->init_state != dfa->init_state_word)
    re_compile_fastmap_iter (bufp, dfa->init_state_word, fastmap);
  if (dfa->init_state != dfa->init_state_nl)
    re_compile_fastmap_iter (bufp, dfa->init_state_nl, fastmap);
  if (dfa->init_state != dfa->init_state_begbuf)
    re_compile_fastmap_iter (bufp, dfa->init_state_begbuf, fastmap);
  bufp->fastmap_accurate = 1;
  return 0;
}
#ifdef _LIBC
weak_alias (__re_compile_fastmap, re_compile_fastmap)
#endif

static inline void
__attribute ((always_inline))
re_set_fastmap (char *fastmap, int icase, int ch)
{
  fastmap[ch] = 1;
  if (icase)
    fastmap[tolower (ch)] = 1;
}

/* Helper function for re_compile_fastmap.
   Compile fastmap for the initial_state INIT_STATE.  */

static void
re_compile_fastmap_iter (regex_t *bufp, const re_dfastate_t *init_state,
			 char *fastmap)
{
  volatile re_dfa_t *dfa = (re_dfa_t *) bufp->buffer;
  int node_cnt;
  int icase = (dfa->mb_cur_max == 1 && (bufp->syntax & RE_ICASE));
  for (node_cnt = 0; node_cnt < init_state->nodes.nelem; ++node_cnt)
    {
      int node = init_state->nodes.elems[node_cnt];
      re_token_type_t type = dfa->nodes[node].type;

      if (type == CHARACTER)
	{
	  re_set_fastmap (fastmap, icase, dfa->nodes[node].opr.c);
#ifdef RE_ENABLE_I18N
	  if ((bufp->syntax & RE_ICASE) && dfa->mb_cur_max > 1)
	    {
	      unsigned char *buf = re_malloc (unsigned char, dfa->mb_cur_max), *p;
	      wchar_t wc;
	      mbstate_t state;

	      p = buf;
	      *p++ = dfa->nodes[node].opr.c;
	      while (++node < dfa->nodes_len
		     &&	dfa->nodes[node].type == CHARACTER
		     && dfa->nodes[node].mb_partial)
		*p++ = dfa->nodes[node].opr.c;
	      memset (&state, '\0', sizeof (state));
	      if (__mbrtowc (&wc, (const char *) buf, p - buf,
			     &state) == p - buf
		  && (__wcrtomb ((char *) buf, towlower (wc), &state)
		      != (size_t) -1))
		re_set_fastmap (fastmap, 0, buf[0]);
	      re_free (buf);
	    }
#endif
	}
      else if (type == SIMPLE_BRACKET)
	{
	  int i, ch;
	  for (i = 0, ch = 0; i < BITSET_WORDS; ++i)
	    {
	      int j;
	      bitset_word_t w = dfa->nodes[node].opr.sbcset[i];
	      for (j = 0; j < BITSET_WORD_BITS; ++j, ++ch)
		if (w & ((bitset_word_t) 1 << j))
		  re_set_fastmap (fastmap, icase, ch);
	    }
	}
#ifdef RE_ENABLE_I18N
      else if (type == COMPLEX_BRACKET)
	{
	  re_charset_t *cset = dfa->nodes[node].opr.mbcset;
	  int i;

# ifdef _LIBC
	  /* See if we have to try all bytes which start multiple collation
	     elements.
	     e.g. In da_DK, we want to catch 'a' since "aa" is a valid
		  collation element, and don't catch 'b' since 'b' is
		  the only collation element which starts from 'b' (and
		  it is caught by SIMPLE_BRACKET).  */
	      if (_NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES) != 0
		  && (cset->ncoll_syms || cset->nranges))
		{
		  const int32_t *table = (const int32_t *)
		    _NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEMB);
		  for (i = 0; i < SBC_MAX; ++i)
		    if (table[i] < 0)
		      re_set_fastmap (fastmap, icase, i);
		}
# endif /* _LIBC */

	  /* See if we have to start the match at all multibyte characters,
	     i.e. where we would not find an invalid sequence.  This only
	     applies to multibyte character sets; for single byte character
	     sets, the SIMPLE_BRACKET again suffices.  */
	  if (dfa->mb_cur_max > 1
	      && (cset->nchar_classes || cset->non_match || cset->nranges
# ifdef _LIBC
		  || cset->nequiv_classes
# endif /* _LIBC */
		 ))
	    {
	      unsigned char c = 0;
	      do
		{
		  mbstate_t mbs;
		  memset (&mbs, 0, sizeof (mbs));
		  if (__mbrtowc (NULL, (char *) &c, 1, &mbs) == (size_t) -2)
		    re_set_fastmap (fastmap, false, (int) c);
		}
	      while (++c != 0);
	    }

	  else
	    {
	      /* ... Else catch all bytes which can start the mbchars.  */
	      for (i = 0; i < cset->nmbchars; ++i)
		{
		  char buf[256];
		  mbstate_t state;
		  memset (&state, '\0', sizeof (state));
		  if (__wcrtomb (buf, cset->mbchars[i], &state) != (size_t) -1)
		    re_set_fastmap (fastmap, icase, *(unsigned char *) buf);
		  if ((bufp->syntax & RE_ICASE) && dfa->mb_cur_max > 1)
		    {
		      if (__wcrtomb (buf, towlower (cset->mbchars[i]), &state)
			  != (size_t) -1)
			re_set_fastmap (fastmap, false, *(unsigned char *) buf);
		    }
		}
	    }
	}
#endif /* RE_ENABLE_I18N */
      else if (type == OP_PERIOD
#ifdef RE_ENABLE_I18N
	       || type == OP_UTF8_PERIOD
#endif /* RE_ENABLE_I18N */
	       || type == END_OF_RE)
	{
	  memset (fastmap, '\1', sizeof (char) * SBC_MAX);
	  if (type == END_OF_RE)
	    bufp->can_be_null = 1;
	  return;
	}
    }
}

/* Entry point for POSIX code.  */
/* regcomp takes a regular expression as a string and compiles it.

   PREG is a regex_t *.  We do not expect any fields to be initialized,
   since POSIX says we shouldn't.  Thus, we set

     `buffer' to the compiled pattern;
     `used' to the length of the compiled pattern;
     `syntax' to RE_SYNTAX_POSIX_EXTENDED if the
       REG_EXTENDED bit in CFLAGS is set; otherwise, to
       RE_SYNTAX_POSIX_BASIC;
     `newline_anchor' to REG_NEWLINE being set in CFLAGS;
     `fastmap' to an allocated space for the fastmap;
     `fastmap_accurate' to zero;
     `re_nsub' to the number of subexpressions in PATTERN.

   PATTERN is the address of the pattern string.

   CFLAGS is a series of bits which affect compilation.

     If REG_EXTENDED is set, we use POSIX extended syntax; otherwise, we
     use POSIX basic syntax.

     If REG_NEWLINE is set, then . and [^...] don't match newline.
     Also, regexec will try a match beginning after every newline.

     If REG_ICASE is set, then we considers upper- and lowercase
     versions of letters to be equivalent when matching.

     If REG_NOSUB is set, then when PREG is passed to regexec, that
     routine will report only success or failure, and nothing about the
     registers.

   It returns 0 if it succeeds, nonzero if it doesn't.  (See regex.h for
   the return codes and their meanings.)  */

int
regcomp (regex_t *__restrict preg,
	 const char *__restrict pattern,
	 int cflags)
{
  reg_errcode_t ret;
  reg_syntax_t syntax = ((cflags & REG_EXTENDED) ? RE_SYNTAX_POSIX_EXTENDED
			 : RE_SYNTAX_POSIX_BASIC);

  preg->buffer = NULL;
  preg->allocated = 0;
  preg->used = 0;

  /* Try to allocate space for the fastmap.  */
  preg->fastmap = re_malloc (char, SBC_MAX);
  if (BE (preg->fastmap == NULL, 0))
    return REG_ESPACE;

  syntax |= (cflags & REG_ICASE) ? RE_ICASE : 0;

  /* If REG_NEWLINE is set, newlines are treated differently.  */
  if (cflags & REG_NEWLINE)
    { /* REG_NEWLINE implies neither . nor [^...] match newline.  */
      syntax &= ~RE_DOT_NEWLINE;
      syntax |= RE_HAT_LISTS_NOT_NEWLINE;
      /* It also changes the matching behavior.  */
      preg->newline_anchor = 1;
    }
  else
    preg->newline_anchor = 0;
  preg->no_sub = !!(cflags & REG_NOSUB);
  preg->translate = NULL;

  ret = re_compile_internal (preg, pattern, strlen (pattern), syntax);

  /* POSIX doesn't distinguish between an unmatched open-group and an
     unmatched close-group: both are REG_EPAREN.  */
  if (ret == REG_ERPAREN)
    ret = REG_EPAREN;

  /* We have already checked preg->fastmap != NULL.  */
  if (BE (ret == REG_NOERROR, 1))
    /* Compute the fastmap now, since regexec cannot modify the pattern
       buffer.  This function never fails in this implementation.  */
    (void) re_compile_fastmap (preg);
  else
    {
      /* Some error occurred while compiling the expression.  */
      re_free (preg->fastmap);
      preg->fastmap = NULL;
    }

  return (int) ret;
}
#ifdef _LIBC
weak_alias (__regcomp, regcomp)
#endif

/* Returns a message corresponding to an error code, ERRCODE, returned
   from either regcomp or regexec.   We don't use PREG here.  */

size_t
regerror(int errcode, UNUSED const regex_t *__restrict preg,
	 char *__restrict errbuf, size_t errbuf_size)
{
  const char *msg;
  size_t msg_size;

  if (BE (errcode < 0
	  || errcode >= (int) (sizeof (__re_error_msgid_idx)
			       / sizeof (__re_error_msgid_idx[0])), 0))
    /* Only error codes returned by the rest of the code should be passed
       to this routine.  If we are given anything else, or if other regex
       code generates an invalid error code, then the program has a bug.
       Dump core so we can fix it.  */
    abort ();

  msg = gettext (__re_error_msgid + __re_error_msgid_idx[errcode]);

  msg_size = strlen (msg) + 1; /* Includes the null.  */

  if (BE (errbuf_size != 0, 1))
    {
      if (BE (msg_size > errbuf_size, 0))
	{
	  memcpy (errbuf, msg, errbuf_size - 1);
	  errbuf[errbuf_size - 1] = 0;
	}
      else
	memcpy (errbuf, msg, msg_size);
    }

  return msg_size;
}
#ifdef _LIBC
weak_alias (__regerror, regerror)
#endif


#ifdef RE_ENABLE_I18N
/* This static array is used for the map to single-byte characters when
   UTF-8 is used.  Otherwise we would allocate memory just to initialize
   it the same all the time.  UTF-8 is the preferred encoding so this is
   a worthwhile optimization.  */
#if __GNUC__ >= 3
static const bitset_t utf8_sb_map = {
  /* Set the first 128 bits.  */
  [0 ... 0x80 / BITSET_WORD_BITS - 1] = BITSET_WORD_MAX
};
#else /* ! (__GNUC__ >= 3) */
static bitset_t utf8_sb_map;
#endif /* __GNUC__ >= 3 */
#endif /* RE_ENABLE_I18N */


static void
free_dfa_content (re_dfa_t *dfa)
{
  unsigned int i;
  int j;

  if (dfa->nodes)
    for (i = 0; i < dfa->nodes_len; ++i)
      free_token (dfa->nodes + i);
  re_free (dfa->nexts);
  for (i = 0; i < dfa->nodes_len; ++i)
    {
      if (dfa->eclosures != NULL)
	re_node_set_free (dfa->eclosures + i);
      if (dfa->inveclosures != NULL)
	re_node_set_free (dfa->inveclosures + i);
      if (dfa->edests != NULL)
	re_node_set_free (dfa->edests + i);
    }
  re_free (dfa->edests);
  re_free (dfa->eclosures);
  re_free (dfa->inveclosures);
  re_free (dfa->nodes);

  if (dfa->state_table)
    for (i = 0; i <= dfa->state_hash_mask; ++i)
      {
	struct re_state_table_entry *entry = dfa->state_table + i;
	for (j = 0; j < entry->num; ++j)
	  {
	    re_dfastate_t *state = entry->array[j];
	    free_state (state);
	  }
	re_free (entry->array);
      }
  re_free (dfa->state_table);
#ifdef RE_ENABLE_I18N
  if (dfa->sb_char != utf8_sb_map)
    re_free (dfa->sb_char);
#endif
  re_free (dfa->subexp_map);
#ifdef DEBUG
  re_free (dfa->re_str);
#endif

  re_free (dfa);
}


/* Free dynamically allocated space used by PREG.  */

void
regfree (regex_t *preg)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  if (BE (dfa != NULL, 1))
    free_dfa_content (dfa);
  preg->buffer = NULL;
  preg->allocated = 0;

  re_free (preg->fastmap);
  preg->fastmap = NULL;

  re_free (preg->translate);
  preg->translate = NULL;
}
#ifdef _LIBC
weak_alias (__regfree, regfree)
#endif

/* Entry points compatible with 4.2 BSD regex library.  We don't define
   them unless specifically requested.  */

#if defined _REGEX_RE_COMP || defined _LIBC

/* BSD has one and only one pattern buffer.  */
static struct re_pattern_buffer re_comp_buf;

char *
# ifdef _LIBC
/* Make these definitions weak in libc, so POSIX programs can redefine
   these names if they don't use our functions, and still use
   regcomp/regexec above without link errors.  */
weak_function
# endif
re_comp (s)
     const char *s;
{
  reg_errcode_t ret;
  char *fastmap;

  if (!s)
    {
      if (!re_comp_buf.buffer)
	return gettext ("No previous regular expression");
      return 0;
    }

  if (re_comp_buf.buffer)
    {
      fastmap = re_comp_buf.fastmap;
      re_comp_buf.fastmap = NULL;
      __regfree (&re_comp_buf);
      memset (&re_comp_buf, '\0', sizeof (re_comp_buf));
      re_comp_buf.fastmap = fastmap;
    }

  if (re_comp_buf.fastmap == NULL)
    {
      re_comp_buf.fastmap = (char *) malloc (SBC_MAX);
      if (re_comp_buf.fastmap == NULL)
	return (char *) gettext (__re_error_msgid
				 + __re_error_msgid_idx[(int) REG_ESPACE]);
    }

  /* Since `re_exec' always passes NULL for the `regs' argument, we
     don't need to initialize the pattern buffer fields which affect it.  */

  /* Match anchors at newlines.  */
  re_comp_buf.newline_anchor = 1;

  ret = re_compile_internal (&re_comp_buf, s, strlen (s), re_syntax_options);

  if (!ret)
    return NULL;

  /* Yes, we're discarding `const' here if !HAVE_LIBINTL.  */
  return (char *) gettext (__re_error_msgid + __re_error_msgid_idx[(int) ret]);
}

#ifdef _LIBC
libc_freeres_fn (free_mem)
{
  __regfree (&re_comp_buf);
}
#endif

#endif /* _REGEX_RE_COMP */

/* Internal entry point.
   Compile the regular expression PATTERN, whose length is LENGTH.
   SYNTAX indicate regular expression's syntax.  */

static reg_errcode_t
re_compile_internal (regex_t *preg, const char * pattern, size_t length,
		     reg_syntax_t syntax)
{
  reg_errcode_t err = REG_NOERROR;
  re_dfa_t *dfa;
  re_string_t regexp;

  /* Initialize the pattern buffer.  */
  preg->fastmap_accurate = 0;
  preg->syntax = syntax;
  preg->not_bol = preg->not_eol = 0;
  preg->used = 0;
  preg->re_nsub = 0;
  preg->can_be_null = 0;
  preg->regs_allocated = REGS_UNALLOCATED;

  /* Initialize the dfa.  */
  dfa = (re_dfa_t *) preg->buffer;
  if (BE (preg->allocated < sizeof (re_dfa_t), 0))
    {
      /* If zero allocated, but buffer is non-null, try to realloc
	 enough space.  This loses if buffer's address is bogus, but
	 that is the user's responsibility.  If ->buffer is NULL this
	 is a simple allocation.  */
      dfa = re_realloc (preg->buffer, re_dfa_t, 1);
      if (dfa == NULL)
	return REG_ESPACE;
      preg->allocated = sizeof (re_dfa_t);
      preg->buffer = (unsigned char *) dfa;
    }
  preg->used = sizeof (re_dfa_t);

  err = init_dfa (dfa, length);
  if (BE (err != REG_NOERROR, 0))
    {
      free_dfa_content (dfa);
      preg->buffer = NULL;
      preg->allocated = 0;
      return err;
    }
#ifdef DEBUG
  /* Note: length+1 will not overflow since it is checked in init_dfa.  */
  dfa->re_str = re_malloc (char, length + 1);
  strncpy (dfa->re_str, pattern, length + 1);
#endif

  __libc_lock_init (dfa->lock);

  err = re_string_construct (&regexp, pattern, length, preg->translate,
			     syntax & RE_ICASE, dfa);
  if (BE (err != REG_NOERROR, 0))
    {
    re_compile_internal_free_return:
      free_workarea_compile (preg);
      re_string_destruct (&regexp);
      free_dfa_content (dfa);
      preg->buffer = NULL;
      preg->allocated = 0;
      return err;
    }

  /* Parse the regular expression, and build a structure tree.  */
  preg->re_nsub = 0;
  dfa->str_tree = parse (&regexp, preg, syntax, &err);
  if (BE (dfa->str_tree == NULL, 0))
    goto re_compile_internal_free_return;

  /* Analyze the tree and create the nfa.  */
  err = analyze (preg);
  if (BE (err != REG_NOERROR, 0))
    goto re_compile_internal_free_return;

#ifdef RE_ENABLE_I18N
  /* If possible, do searching in single byte encoding to speed things up.  */
  if (dfa->is_utf8 && !(syntax & RE_ICASE) && preg->translate == NULL)
    optimize_utf8 (dfa);
#endif

  /* Then create the initial state of the dfa.  */
  err = create_initial_state (dfa);

  /* Release work areas.  */
  free_workarea_compile (preg);
  re_string_destruct (&regexp);

  if (BE (err != REG_NOERROR, 0))
    {
      free_dfa_content (dfa);
      preg->buffer = NULL;
      preg->allocated = 0;
    }

  return err;
}

/* Initialize DFA.  We use the length of the regular expression PAT_LEN
   as the initial length of some arrays.  */

static reg_errcode_t
init_dfa (re_dfa_t *dfa, size_t pat_len)
{
  unsigned int table_size;

  memset (dfa, '\0', sizeof (re_dfa_t));

  /* Force allocation of str_tree_storage the first time.  */
  dfa->str_tree_storage_idx = BIN_TREE_STORAGE_SIZE;

  /* Avoid overflows.  */
  if (pat_len == SIZE_MAX)
    return REG_ESPACE;

  dfa->nodes_alloc = pat_len + 1;
  dfa->nodes = re_malloc (re_token_t, dfa->nodes_alloc);

  /*  table_size = 2 ^ ceil(log pat_len) */
  for (table_size = 1; ; table_size <<= 1)
    if (table_size > pat_len)
      break;
//@Venrob: This needs EXPLICIT conversion in C++ -Z (18th March, 2019)
//Uncomment the following line, figure out the conversion, fix it, and you should be good to go. 
  //dfa->state_table = calloc (sizeof (struct re_state_table_entry), table_size);
    //NEEDS to be
  //dfa->state_table = (*typecast here)calloc (sizeof (struct re_state_table_entry), table_size);
  dfa->state_hash_mask = table_size - 1;

  dfa->mb_cur_max = MB_CUR_MAX;
#ifdef _LIBC
  if (dfa->mb_cur_max == 6
      && strcmp (_NL_CURRENT (LC_CTYPE, _NL_CTYPE_CODESET_NAME), "UTF-8") == 0)
    dfa->is_utf8 = 1;
  dfa->map_notascii = (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_MAP_TO_NONASCII)
		       != 0);
#else
  dfa->is_utf8 = 1;
  /* We check exhaustively in the loop below if this charset is a
     superset of ASCII.  */
  dfa->map_notascii = 0;
#endif

#ifdef RE_ENABLE_I18N
  if (dfa->mb_cur_max > 1)
    {
      if (dfa->is_utf8)
        {
#if !defined(__GNUC__) || __GNUC__ < 3
	  static short utf8_sb_map_inited = 0;

	  if (! utf8_sb_map_inited)
	    {
		int i;

	  	utf8_sb_map_inited = 0;
		for (i = 0; i <= 0x80 / BITSET_WORD_BITS - 1; i++)
		  utf8_sb_map[i] = BITSET_WORD_MAX;
	    }
#endif
	  dfa->sb_char = (re_bitset_ptr_t) utf8_sb_map;
	}
      else
	{
	  int i, j, ch;

	  dfa->sb_char = (re_bitset_ptr_t) calloc (sizeof (bitset_t), 1);
	  if (BE (dfa->sb_char == NULL, 0))
	    return REG_ESPACE;

	  /* Set the bits corresponding to single byte chars.  */
	  for (i = 0, ch = 0; i < BITSET_WORDS; ++i)
	    for (j = 0; j < BITSET_WORD_BITS; ++j, ++ch)
	      {
		wint_t wch = __btowc (ch);
		if (wch != WEOF)
		  dfa->sb_char[i] |= (bitset_word_t) 1 << j;
# ifndef _LIBC
		if (isascii (ch) && wch != ch)
		  dfa->map_notascii = 1;
# endif
	      }
	}
    }
#endif

  if (BE (dfa->nodes == NULL || dfa->state_table == NULL, 0))
    return REG_ESPACE;
  return REG_NOERROR;
}

/* Initialize WORD_CHAR table, which indicate which character is
   "word".  In this case "word" means that it is the word construction
   character used by some operators like "\<", "\>", etc.  */

static void
internal_function
init_word_char (re_dfa_t *dfa)
{
  int i, j, ch;
  dfa->word_ops_used = 1;
  for (i = 0, ch = 0; i < BITSET_WORDS; ++i)
    for (j = 0; j < BITSET_WORD_BITS; ++j, ++ch)
      if (isalnum (ch) || ch == '_')
	dfa->word_char[i] |= (bitset_word_t) 1 << j;
}

/* Free the work area which are only used while compiling.  */

static void
free_workarea_compile (regex_t *preg)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  bin_tree_storage_t *storage, *next;
  for (storage = dfa->str_tree_storage; storage; storage = next)
    {
      next = storage->next;
      re_free (storage);
    }
  dfa->str_tree_storage = NULL;
  dfa->str_tree_storage_idx = BIN_TREE_STORAGE_SIZE;
  dfa->str_tree = NULL;
  re_free (dfa->org_indices);
  dfa->org_indices = NULL;
}

/* Create initial states for all contexts.  */

static reg_errcode_t
create_initial_state (re_dfa_t *dfa)
{
  int first, i;
  reg_errcode_t err;
  re_node_set init_nodes;

  /* Initial states have the epsilon closure of the node which is
     the first node of the regular expression.  */
  first = dfa->str_tree->first->node_idx;
  dfa->init_node = first;
  err = re_node_set_init_copy (&init_nodes, dfa->eclosures + first);
  if (BE (err != REG_NOERROR, 0))
    return err;

  /* The back-references which are in initial states can epsilon transit,
     since in this case all of the subexpressions can be null.
     Then we add epsilon closures of the nodes which are the next nodes of
     the back-references.  */
  if (dfa->nbackref > 0)
    for (i = 0; i < init_nodes.nelem; ++i)
      {
	int node_idx = init_nodes.elems[i];
	re_token_type_t type = dfa->nodes[node_idx].type;

	int clexp_idx;
	if (type != OP_BACK_REF)
	  continue;
	for (clexp_idx = 0; clexp_idx < init_nodes.nelem; ++clexp_idx)
	  {
	    re_token_t *clexp_node;
	    clexp_node = dfa->nodes + init_nodes.elems[clexp_idx];
	    if (clexp_node->type == OP_CLOSE_SUBEXP
		&& clexp_node->opr.idx == dfa->nodes[node_idx].opr.idx)
	      break;
	  }
	if (clexp_idx == init_nodes.nelem)
	  continue;

	if (type == OP_BACK_REF)
	  {
	    int dest_idx = dfa->edests[node_idx].elems[0];
	    if (!re_node_set_contains (&init_nodes, dest_idx))
	      {
		reg_errcode_t err = re_node_set_merge (&init_nodes,
						       dfa->eclosures
						       + dest_idx);
		if (err != REG_NOERROR)
		  return err;
		i = 0;
	      }
	  }
      }

  /* It must be the first time to invoke acquire_state.  */
  dfa->init_state = re_acquire_state_context (&err, dfa, &init_nodes, 0);
  /* We don't check ERR here, since the initial state must not be NULL.  */
  if (BE (dfa->init_state == NULL, 0))
    return err;
  if (dfa->init_state->has_constraint)
    {
      dfa->init_state_word = re_acquire_state_context (&err, dfa, &init_nodes,
						       CONTEXT_WORD);
      dfa->init_state_nl = re_acquire_state_context (&err, dfa, &init_nodes,
						     CONTEXT_NEWLINE);
      dfa->init_state_begbuf = re_acquire_state_context (&err, dfa,
							 &init_nodes,
							 CONTEXT_NEWLINE
							 | CONTEXT_BEGBUF);
      if (BE (dfa->init_state_word == NULL || dfa->init_state_nl == NULL
	      || dfa->init_state_begbuf == NULL, 0))
	return err;
    }
  else
    dfa->init_state_word = dfa->init_state_nl
      = dfa->init_state_begbuf = dfa->init_state;

  re_node_set_free (&init_nodes);
  return REG_NOERROR;
}

#ifdef RE_ENABLE_I18N
/* If it is possible to do searching in single byte encoding instead of UTF-8
   to speed things up, set dfa->mb_cur_max to 1, clear is_utf8 and change
   DFA nodes where needed.  */

static void
optimize_utf8 (re_dfa_t *dfa)
{
  int node, i, mb_chars = 0, has_period = 0;

  for (node = 0; node < dfa->nodes_len; ++node)
    switch (dfa->nodes[node].type)
      {
      case CHARACTER:
	if (dfa->nodes[node].opr.c >= 0x80)
	  mb_chars = 1;
	break;
      case ANCHOR:
	switch (dfa->nodes[node].opr.ctx_type)
	  {
	  case LINE_FIRST:
	  case LINE_LAST:
	  case BUF_FIRST:
	  case BUF_LAST:
	    break;
	  default:
	    /* Word anchors etc. cannot be handled.  It's okay to test
	       opr.ctx_type since constraints (for all DFA nodes) are
	       created by ORing one or more opr.ctx_type values.  */
	    return;
	  }
	break;
      case OP_PERIOD:
	has_period = 1;
	break;
      case OP_BACK_REF:
      case OP_ALT:
      case END_OF_RE:
      case OP_DUP_ASTERISK:
      case OP_OPEN_SUBEXP:
      case OP_CLOSE_SUBEXP:
	break;
      case COMPLEX_BRACKET:
	return;
      case SIMPLE_BRACKET:
	/* Just double check.  The non-ASCII range starts at 0x80.  */
	assert (0x80 % BITSET_WORD_BITS == 0);
	for (i = 0x80 / BITSET_WORD_BITS; i < BITSET_WORDS; ++i)
	  if (dfa->nodes[node].opr.sbcset[i])
	    return;
	break;
      default:
	abort ();
      }

  if (mb_chars || has_period)
    for (node = 0; node < dfa->nodes_len; ++node)
      {
	if (dfa->nodes[node].type == CHARACTER
	    && dfa->nodes[node].opr.c >= 0x80)
	  dfa->nodes[node].mb_partial = 0;
	else if (dfa->nodes[node].type == OP_PERIOD)
	  dfa->nodes[node].type = OP_UTF8_PERIOD;
      }

  /* The search can be in single byte locale.  */
  dfa->mb_cur_max = 1;
  dfa->is_utf8 = 0;
  dfa->has_mb_node = dfa->nbackref > 0 || has_period;
}
#endif

/* Analyze the structure tree, and calculate "first", "next", "edest",
   "eclosure", and "inveclosure".  */

static reg_errcode_t
analyze (regex_t *preg)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  reg_errcode_t ret;

  /* Allocate arrays.  */
  dfa->nexts = re_malloc (int, dfa->nodes_alloc);
  dfa->org_indices = re_malloc (int, dfa->nodes_alloc);
  dfa->edests = re_malloc (re_node_set, dfa->nodes_alloc);
  dfa->eclosures = re_malloc (re_node_set, dfa->nodes_alloc);
  if (BE (dfa->nexts == NULL || dfa->org_indices == NULL || dfa->edests == NULL
	  || dfa->eclosures == NULL, 0))
    return REG_ESPACE;

  dfa->subexp_map = re_malloc (int, preg->re_nsub);
  if (dfa->subexp_map != NULL)
    {
      unsigned int i;
      for (i = 0; i < preg->re_nsub; i++)
	dfa->subexp_map[i] = i;
      preorder (dfa->str_tree, optimize_subexps, dfa);
      for (i = 0; i < preg->re_nsub; i++)
	if (dfa->subexp_map[i] != (int)i)
	  break;
      if (i == preg->re_nsub)
	{
	  free (dfa->subexp_map);
	  dfa->subexp_map = NULL;
	}
    }

  ret = postorder (dfa->str_tree, lower_subexps, preg);
  if (BE (ret != REG_NOERROR, 0))
    return ret;
  ret = postorder (dfa->str_tree, calc_first, dfa);
  if (BE (ret != REG_NOERROR, 0))
    return ret;
  preorder (dfa->str_tree, calc_next, dfa);
  ret = preorder (dfa->str_tree, link_nfa_nodes, dfa);
  if (BE (ret != REG_NOERROR, 0))
    return ret;
  ret = calc_eclosure (dfa);
  if (BE (ret != REG_NOERROR, 0))
    return ret;

  /* We only need this during the prune_impossible_nodes pass in regexec.c;
     skip it if p_i_n will not run, as calc_inveclosure can be quadratic.  */
  if ((!preg->no_sub && preg->re_nsub > 0 && dfa->has_plural_match)
      || dfa->nbackref)
    {
      dfa->inveclosures = re_malloc (re_node_set, dfa->nodes_len);
      if (BE (dfa->inveclosures == NULL, 0))
	return REG_ESPACE;
      ret = calc_inveclosure (dfa);
    }

  return ret;
}

/* Our parse trees are very unbalanced, so we cannot use a stack to
   implement parse tree visits.  Instead, we use parent pointers and
   some hairy code in these two functions.  */
static reg_errcode_t
postorder (bin_tree_t *root, reg_errcode_t (fn (void *, bin_tree_t *)),
	   void *extra)
{
  bin_tree_t *node, *prev;

  for (node = root; ; )
    {
      /* Descend down the tree, preferably to the left (or to the right
	 if that's the only child).  */
      while (node->left || node->right)
	if (node->left)
	  node = node->left;
	else
	  node = node->right;

      do
	{
	  reg_errcode_t err = fn (extra, node);
	  if (BE (err != REG_NOERROR, 0))
	    return err;
	  if (node->parent == NULL)
	    return REG_NOERROR;
	  prev = node;
	  node = node->parent;
	}
      /* Go up while we have a node that is reached from the right.  */
      while (node->right == prev || node->right == NULL);
      node = node->right;
    }
}

static reg_errcode_t
preorder (bin_tree_t *root, reg_errcode_t (fn (void *, bin_tree_t *)),
	  void *extra)
{
  bin_tree_t *node;

  for (node = root; ; )
    {
      reg_errcode_t err = fn (extra, node);
      if (BE (err != REG_NOERROR, 0))
	return err;

      /* Go to the left node, or up and to the right.  */
      if (node->left)
	node = node->left;
      else
	{
	  bin_tree_t *prev = NULL;
	  while (node->right == prev || node->right == NULL)
	    {
	      prev = node;
	      node = node->parent;
	      if (!node)
		return REG_NOERROR;
	    }
	  node = node->right;
	}
    }
}

/* Optimization pass: if a SUBEXP is entirely contained, strip it and tell
   re_search_internal to map the inner one's opr.idx to this one's.  Adjust
   backreferences as well.  Requires a preorder visit.  */
static reg_errcode_t
optimize_subexps (void *extra, bin_tree_t *node)
{
  re_dfa_t *dfa = (re_dfa_t *) extra;

  if (node->token.type == OP_BACK_REF && dfa->subexp_map)
    {
      int idx = node->token.opr.idx;
      node->token.opr.idx = dfa->subexp_map[idx];
      dfa->used_bkref_map |= 1 << node->token.opr.idx;
    }

  else if (node->token.type == SUBEXP
	   && node->left && node->left->token.type == SUBEXP)
    {
      int other_idx = node->left->token.opr.idx;

      node->left = node->left->left;
      if (node->left)
	node->left->parent = node;

      dfa->subexp_map[other_idx] = dfa->subexp_map[node->token.opr.idx];
      if (other_idx < BITSET_WORD_BITS)
	  dfa->used_bkref_map &= ~((bitset_word_t) 1 << other_idx);
    }

  return REG_NOERROR;
}

/* Lowering pass: Turn each SUBEXP node into the appropriate concatenation
   of OP_OPEN_SUBEXP, the body of the SUBEXP (if any) and OP_CLOSE_SUBEXP.  */
static reg_errcode_t
lower_subexps (void *extra, bin_tree_t *node)
{
  regex_t *preg = (regex_t *) extra;
  reg_errcode_t err = REG_NOERROR;

  if (node->left && node->left->token.type == SUBEXP)
    {
      node->left = lower_subexp (&err, preg, node->left);
      if (node->left)
	node->left->parent = node;
    }
  if (node->right && node->right->token.type == SUBEXP)
    {
      node->right = lower_subexp (&err, preg, node->right);
      if (node->right)
	node->right->parent = node;
    }

  return err;
}

static bin_tree_t *
lower_subexp (reg_errcode_t *err, regex_t *preg, bin_tree_t *node)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  bin_tree_t *body = node->left;
  bin_tree_t *op, *cls, *tree1, *tree;

  if (preg->no_sub
      /* We do not optimize empty subexpressions, because otherwise we may
	 have bad CONCAT nodes with NULL children.  This is obviously not
	 very common, so we do not lose much.  An example that triggers
	 this case is the sed "script" /\(\)/x.  */
      && node->left != NULL
      && (node->token.opr.idx >= BITSET_WORD_BITS
	  || !(dfa->used_bkref_map
	       & ((bitset_word_t) 1 << node->token.opr.idx))))
    return node->left;

  /* Convert the SUBEXP node to the concatenation of an
     OP_OPEN_SUBEXP, the contents, and an OP_CLOSE_SUBEXP.  */
  op = create_tree (dfa, NULL, NULL, OP_OPEN_SUBEXP);
  cls = create_tree (dfa, NULL, NULL, OP_CLOSE_SUBEXP);
  tree1 = body ? create_tree (dfa, body, cls, CONCAT) : cls;
  tree = create_tree (dfa, op, tree1, CONCAT);
  if (BE (tree == NULL || tree1 == NULL || op == NULL || cls == NULL, 0))
    {
      *err = REG_ESPACE;
      return NULL;
    }

  op->token.opr.idx = cls->token.opr.idx = node->token.opr.idx;
  op->token.opt_subexp = cls->token.opt_subexp = node->token.opt_subexp;
  return tree;
}

/* Pass 1 in building the NFA: compute FIRST and create unlinked automaton
   nodes.  Requires a postorder visit.  */
static reg_errcode_t
calc_first (void *extra, bin_tree_t *node)
{
  re_dfa_t *dfa = (re_dfa_t *) extra;
  if (node->token.type == CONCAT)
    {
      node->first = node->left->first;
      node->node_idx = node->left->node_idx;
    }
  else
    {
      node->first = node;
      node->node_idx = re_dfa_add_node (dfa, node->token);
      if (BE (node->node_idx == -1, 0))
	return REG_ESPACE;
      if (node->token.type == ANCHOR)
	dfa->nodes[node->node_idx].constraint = node->token.opr.ctx_type;
    }
  return REG_NOERROR;
}

/* Pass 2: compute NEXT on the tree.  Preorder visit.  */
static reg_errcode_t
calc_next (UNUSED void *extra, bin_tree_t *node)
{
  switch (node->token.type)
    {
    case OP_DUP_ASTERISK:
      node->left->next = node;
      break;
    case CONCAT:
      node->left->next = node->right->first;
      node->right->next = node->next;
      break;
    default:
      if (node->left)
	node->left->next = node->next;
      if (node->right)
	node->right->next = node->next;
      break;
    }
  return REG_NOERROR;
}

/* Pass 3: link all DFA nodes to their NEXT node (any order will do).  */
static reg_errcode_t
link_nfa_nodes (void *extra, bin_tree_t *node)
{
  re_dfa_t *dfa = (re_dfa_t *) extra;
  int idx = node->node_idx;
  reg_errcode_t err = REG_NOERROR;

  switch (node->token.type)
    {
    case CONCAT:
      break;

    case END_OF_RE:
      assert (node->next == NULL);
      break;

    case OP_DUP_ASTERISK:
    case OP_ALT:
      {
	int left, right;
	dfa->has_plural_match = 1;
	if (node->left != NULL)
	  left = node->left->first->node_idx;
	else
	  left = node->next->node_idx;
	if (node->right != NULL)
	  right = node->right->first->node_idx;
	else
	  right = node->next->node_idx;
	assert (left > -1);
	assert (right > -1);
	err = re_node_set_init_2 (dfa->edests + idx, left, right);
      }
      break;

    case ANCHOR:
    case OP_OPEN_SUBEXP:
    case OP_CLOSE_SUBEXP:
      err = re_node_set_init_1 (dfa->edests + idx, node->next->node_idx);
      break;

    case OP_BACK_REF:
      dfa->nexts[idx] = node->next->node_idx;
      if (node->token.type == OP_BACK_REF)
	err = re_node_set_init_1 (dfa->edests + idx, dfa->nexts[idx]);
      break;

    default:
      assert (!IS_EPSILON_NODE (node->token.type));
      dfa->nexts[idx] = node->next->node_idx;
      break;
    }

  return err;
}

/* Duplicate the epsilon closure of the node ROOT_NODE.
   Note that duplicated nodes have constraint INIT_CONSTRAINT in addition
   to their own constraint.  */

static reg_errcode_t
internal_function
duplicate_node_closure (re_dfa_t *dfa, int top_org_node, int top_clone_node,
			int root_node, unsigned int init_constraint)
{
  int org_node, clone_node, ret;
  unsigned int constraint = init_constraint;
  for (org_node = top_org_node, clone_node = top_clone_node;;)
    {
      int org_dest, clone_dest;
      if (dfa->nodes[org_node].type == OP_BACK_REF)
	{
	  /* If the back reference epsilon-transit, its destination must
	     also have the constraint.  Then duplicate the epsilon closure
	     of the destination of the back reference, and store it in
	     edests of the back reference.  */
	  org_dest = dfa->nexts[org_node];
	  re_node_set_empty (dfa->edests + clone_node);
	  clone_dest = duplicate_node (dfa, org_dest, constraint);
	  if (BE (clone_dest == -1, 0))
	    return REG_ESPACE;
	  dfa->nexts[clone_node] = dfa->nexts[org_node];
	  ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
	  if (BE (ret < 0, 0))
	    return REG_ESPACE;
	}
      else if (dfa->edests[org_node].nelem == 0)
	{
	  /* In case of the node can't epsilon-transit, don't duplicate the
	     destination and store the original destination as the
	     destination of the node.  */
	  dfa->nexts[clone_node] = dfa->nexts[org_node];
	  break;
	}
      else if (dfa->edests[org_node].nelem == 1)
	{
	  /* In case of the node can epsilon-transit, and it has only one
	     destination.  */
	  org_dest = dfa->edests[org_node].elems[0];
	  re_node_set_empty (dfa->edests + clone_node);
	  /* If the node is root_node itself, it means the epsilon clsoure
	     has a loop.   Then tie it to the destination of the root_node.  */
	  if (org_node == root_node && clone_node != org_node)
	    {
	      ret = re_node_set_insert (dfa->edests + clone_node, org_dest);
	      if (BE (ret < 0, 0))
		return REG_ESPACE;
	      break;
	    }
	  /* In case of the node has another constraint, add it.  */
	  constraint |= dfa->nodes[org_node].constraint;
	  clone_dest = duplicate_node (dfa, org_dest, constraint);
	  if (BE (clone_dest == -1, 0))
	    return REG_ESPACE;
	  ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
	  if (BE (ret < 0, 0))
	    return REG_ESPACE;
	}
      else /* dfa->edests[org_node].nelem == 2 */
	{
	  /* In case of the node can epsilon-transit, and it has two
	     destinations. In the bin_tree_t and DFA, that's '|' and '*'.   */
	  org_dest = dfa->edests[org_node].elems[0];
	  re_node_set_empty (dfa->edests + clone_node);
	  /* Search for a duplicated node which satisfies the constraint.  */
	  clone_dest = search_duplicated_node (dfa, org_dest, constraint);
	  if (clone_dest == -1)
	    {
	      /* There is no such duplicated node, create a new one.  */
	      reg_errcode_t err;
	      clone_dest = duplicate_node (dfa, org_dest, constraint);
	      if (BE (clone_dest == -1, 0))
		return REG_ESPACE;
	      ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
	      if (BE (ret < 0, 0))
		return REG_ESPACE;
	      err = duplicate_node_closure (dfa, org_dest, clone_dest,
					    root_node, constraint);
	      if (BE (err != REG_NOERROR, 0))
		return err;
	    }
	  else
	    {
	      /* There is a duplicated node which satisfies the constraint,
		 use it to avoid infinite loop.  */
	      ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
	      if (BE (ret < 0, 0))
		return REG_ESPACE;
	    }

	  org_dest = dfa->edests[org_node].elems[1];
	  clone_dest = duplicate_node (dfa, org_dest, constraint);
	  if (BE (clone_dest == -1, 0))
	    return REG_ESPACE;
	  ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
	  if (BE (ret < 0, 0))
	    return REG_ESPACE;
	}
      org_node = org_dest;
      clone_node = clone_dest;
    }
  return REG_NOERROR;
}

/* Search for a node which is duplicated from the node ORG_NODE, and
   satisfies the constraint CONSTRAINT.  */

static int
search_duplicated_node (const re_dfa_t *dfa, int org_node,
			unsigned int constraint)
{
  int idx;
  for (idx = dfa->nodes_len - 1; dfa->nodes[idx].duplicated && idx > 0; --idx)
    {
      if (org_node == dfa->org_indices[idx]
	  && constraint == dfa->nodes[idx].constraint)
	return idx; /* Found.  */
    }
  return -1; /* Not found.  */
}

/* Duplicate the node whose index is ORG_IDX and set the constraint CONSTRAINT.
   Return the index of the new node, or -1 if insufficient storage is
   available.  */

static int
duplicate_node (re_dfa_t *dfa, int org_idx, unsigned int constraint)
{
  int dup_idx = re_dfa_add_node (dfa, dfa->nodes[org_idx]);
  if (BE (dup_idx != -1, 1))
    {
      dfa->nodes[dup_idx].constraint = constraint;
      dfa->nodes[dup_idx].constraint |= dfa->nodes[org_idx].constraint;
      dfa->nodes[dup_idx].duplicated = 1;

      /* Store the index of the original node.  */
      dfa->org_indices[dup_idx] = org_idx;
    }
  return dup_idx;
}

static reg_errcode_t
calc_inveclosure (re_dfa_t *dfa)
{
  int ret;
  unsigned int src, idx;
  for (idx = 0; idx < dfa->nodes_len; ++idx)
    re_node_set_init_empty (dfa->inveclosures + idx);

  for (src = 0; src < dfa->nodes_len; ++src)
    {
      int *elems = dfa->eclosures[src].elems;
      int idx;
      for (idx = 0; idx < dfa->eclosures[src].nelem; ++idx)
	{
	  ret = re_node_set_insert_last (dfa->inveclosures + elems[idx], src);
	  if (BE (ret == -1, 0))
	    return REG_ESPACE;
	}
    }

  return REG_NOERROR;
}

/* Calculate "eclosure" for all the node in DFA.  */

static reg_errcode_t
calc_eclosure (re_dfa_t *dfa)
{
  size_t node_idx;
  int incomplete;
#ifdef DEBUG
  assert (dfa->nodes_len > 0);
#endif
  incomplete = 0;
  /* For each nodes, calculate epsilon closure.  */
  for (node_idx = 0; ; ++node_idx)
    {
      reg_errcode_t err;
      re_node_set eclosure_elem;
      if (node_idx == dfa->nodes_len)
	{
	  if (!incomplete)
	    break;
	  incomplete = 0;
	  node_idx = 0;
	}

#ifdef DEBUG
      assert (dfa->eclosures[node_idx].nelem != -1);
#endif

      /* If we have already calculated, skip it.  */
      if (dfa->eclosures[node_idx].nelem != 0)
	continue;
      /* Calculate epsilon closure of `node_idx'.  */
      err = calc_eclosure_iter (&eclosure_elem, dfa, node_idx, 1);
      if (BE (err != REG_NOERROR, 0))
	return err;

      if (dfa->eclosures[node_idx].nelem == 0)
	{
	  incomplete = 1;
	  re_node_set_free (&eclosure_elem);
	}
    }
  return REG_NOERROR;
}

/* Calculate epsilon closure of NODE.  */

static reg_errcode_t
calc_eclosure_iter (re_node_set *new_set, re_dfa_t *dfa, int node, int root)
{
  reg_errcode_t err;
  int i;
  re_node_set eclosure;
  int ret;
  int incomplete = 0;
  err = re_node_set_alloc (&eclosure, dfa->edests[node].nelem + 1);
  if (BE (err != REG_NOERROR, 0))
    return err;

  /* This indicates that we are calculating this node now.
     We reference this value to avoid infinite loop.  */
  dfa->eclosures[node].nelem = -1;

  /* If the current node has constraints, duplicate all nodes
     since they must inherit the constraints.  */
  if (dfa->nodes[node].constraint
      && dfa->edests[node].nelem
      && !dfa->nodes[dfa->edests[node].elems[0]].duplicated)
    {
      err = duplicate_node_closure (dfa, node, node, node,
				    dfa->nodes[node].constraint);
      if (BE (err != REG_NOERROR, 0))
	return err;
    }

  /* Expand each epsilon destination nodes.  */
  if (IS_EPSILON_NODE(dfa->nodes[node].type))
    for (i = 0; i < dfa->edests[node].nelem; ++i)
      {
	re_node_set eclosure_elem;
	int edest = dfa->edests[node].elems[i];
	/* If calculating the epsilon closure of `edest' is in progress,
	   return intermediate result.  */
	if (dfa->eclosures[edest].nelem == -1)
	  {
	    incomplete = 1;
	    continue;
	  }
	/* If we haven't calculated the epsilon closure of `edest' yet,
	   calculate now. Otherwise use calculated epsilon closure.  */
	if (dfa->eclosures[edest].nelem == 0)
	  {
	    err = calc_eclosure_iter (&eclosure_elem, dfa, edest, 0);
	    if (BE (err != REG_NOERROR, 0))
	      return err;
	  }
	else
	  eclosure_elem = dfa->eclosures[edest];
	/* Merge the epsilon closure of `edest'.  */
	err = re_node_set_merge (&eclosure, &eclosure_elem);
	if (BE (err != REG_NOERROR, 0))
	  return err;
	/* If the epsilon closure of `edest' is incomplete,
	   the epsilon closure of this node is also incomplete.  */
	if (dfa->eclosures[edest].nelem == 0)
	  {
	    incomplete = 1;
	    re_node_set_free (&eclosure_elem);
	  }
      }

  /* An epsilon closure includes itself.  */
  ret = re_node_set_insert (&eclosure, node);
  if (BE (ret < 0, 0))
    return REG_ESPACE;
  if (incomplete && !root)
    dfa->eclosures[node].nelem = 0;
  else
    dfa->eclosures[node] = eclosure;
  *new_set = eclosure;
  return REG_NOERROR;
}

/* Functions for token which are used in the parser.  */

/* Fetch a token from INPUT.
   We must not use this function inside bracket expressions.  */

static void
internal_function
fetch_token (re_token_t *result, re_string_t *input, reg_syntax_t syntax)
{
  re_string_skip_bytes (input, peek_token (result, input, syntax));
}

/* Peek a token from INPUT, and return the length of the token.
   We must not use this function inside bracket expressions.  */

static int
internal_function
peek_token (re_token_t *token, re_string_t *input, reg_syntax_t syntax)
{
  unsigned char c;

  if (re_string_eoi (input))
    {
      token->type = END_OF_RE;
      return 0;
    }

  c = re_string_peek_byte (input, 0);
  token->opr.c = c;

  token->word_char = 0;
#ifdef RE_ENABLE_I18N
  token->mb_partial = 0;
  if (input->mb_cur_max > 1 &&
      !re_string_first_byte (input, re_string_cur_idx (input)))
    {
      token->type = CHARACTER;
      token->mb_partial = 1;
      return 1;
    }
#endif
  if (c == '\\')
    {
      unsigned char c2;
      if (re_string_cur_idx (input) + 1 >= re_string_length (input))
	{
	  token->type = BACK_SLASH;
	  return 1;
	}

      c2 = re_string_peek_byte_case (input, 1);
      token->opr.c = c2;
      token->type = CHARACTER;
#ifdef RE_ENABLE_I18N
      if (input->mb_cur_max > 1)
	{
	  wint_t wc = re_string_wchar_at (input,
					  re_string_cur_idx (input) + 1);
	  token->word_char = IS_WIDE_WORD_CHAR (wc) != 0;
	}
      else
#endif
	token->word_char = IS_WORD_CHAR (c2) != 0;

      switch (c2)
	{
	case '|':
	  if (!(syntax & RE_LIMITED_OPS) && !(syntax & RE_NO_BK_VBAR))
	    token->type = OP_ALT;
	  break;
	case '1': case '2': case '3': case '4': case '5':
	case '6': case '7': case '8': case '9':
	  if (!(syntax & RE_NO_BK_REFS))
	    {
	      token->type = OP_BACK_REF;
	      token->opr.idx = c2 - '1';
	    }
	  break;
	case '<':
	  if (!(syntax & RE_NO_GNU_OPS))
	    {
	      token->type = ANCHOR;
	      token->opr.ctx_type = WORD_FIRST;
	    }
	  break;
	case '>':
	  if (!(syntax & RE_NO_GNU_OPS))
	    {
	      token->type = ANCHOR;
	      token->opr.ctx_type = WORD_LAST;
	    }
	  break;
	case 'b':
	  if (!(syntax & RE_NO_GNU_OPS))
	    {
	      token->type = ANCHOR;
	      token->opr.ctx_type = WORD_DELIM;
	    }
	  break;
	case 'B':
	  if (!(syntax & RE_NO_GNU_OPS))
	    {
	      token->type = ANCHOR;
	      token->opr.ctx_type = NOT_WORD_DELIM;
	    }
	  break;
	case 'w':
	  if (!(syntax & RE_NO_GNU_OPS))
	    token->type = OP_WORD;
	  break;
	case 'W':
	  if (!(syntax & RE_NO_GNU_OPS))
	    token->type = OP_NOTWORD;
	  break;
	case 's':
	  if (!(syntax & RE_NO_GNU_OPS))
	    token->type = OP_SPACE;
	  break;
	case 'S':
	  if (!(syntax & RE_NO_GNU_OPS))
	    token->type = OP_NOTSPACE;
	  break;
	case '`':
	  if (!(syntax & RE_NO_GNU_OPS))
	    {
	      token->type = ANCHOR;
	      token->opr.ctx_type = BUF_FIRST;
	    }
	  break;
	case '\'':
	  if (!(syntax & RE_NO_GNU_OPS))
	    {
	      token->type = ANCHOR;
	      token->opr.ctx_type = BUF_LAST;
	    }
	  break;
	case '(':
	  if (!(syntax & RE_NO_BK_PARENS))
	    token->type = OP_OPEN_SUBEXP;
	  break;
	case ')':
	  if (!(syntax & RE_NO_BK_PARENS))
	    token->type = OP_CLOSE_SUBEXP;
	  break;
	case '+':
	  if (!(syntax & RE_LIMITED_OPS) && (syntax & RE_BK_PLUS_QM))
	    token->type = OP_DUP_PLUS;
	  break;
	case '?':
	  if (!(syntax & RE_LIMITED_OPS) && (syntax & RE_BK_PLUS_QM))
	    token->type = OP_DUP_QUESTION;
	  break;
	case '{':
	  if ((syntax & RE_INTERVALS) && (!(syntax & RE_NO_BK_BRACES)))
	    token->type = OP_OPEN_DUP_NUM;
	  break;
	case '}':
	  if ((syntax & RE_INTERVALS) && (!(syntax & RE_NO_BK_BRACES)))
	    token->type = OP_CLOSE_DUP_NUM;
	  break;
	default:
	  break;
	}
      return 2;
    }

  token->type = CHARACTER;
#ifdef RE_ENABLE_I18N
  if (input->mb_cur_max > 1)
    {
      wint_t wc = re_string_wchar_at (input, re_string_cur_idx (input));
      token->word_char = IS_WIDE_WORD_CHAR (wc) != 0;
    }
  else
#endif
    token->word_char = IS_WORD_CHAR (token->opr.c);

  switch (c)
    {
    case '\n':
      if (syntax & RE_NEWLINE_ALT)
	token->type = OP_ALT;
      break;
    case '|':
      if (!(syntax & RE_LIMITED_OPS) && (syntax & RE_NO_BK_VBAR))
	token->type = OP_ALT;
      break;
    case '*':
      token->type = OP_DUP_ASTERISK;
      break;
    case '+':
      if (!(syntax & RE_LIMITED_OPS) && !(syntax & RE_BK_PLUS_QM))
	token->type = OP_DUP_PLUS;
      break;
    case '?':
      if (!(syntax & RE_LIMITED_OPS) && !(syntax & RE_BK_PLUS_QM))
	token->type = OP_DUP_QUESTION;
      break;
    case '{':
      if ((syntax & RE_INTERVALS) && (syntax & RE_NO_BK_BRACES))
	token->type = OP_OPEN_DUP_NUM;
      break;
    case '}':
      if ((syntax & RE_INTERVALS) && (syntax & RE_NO_BK_BRACES))
	token->type = OP_CLOSE_DUP_NUM;
      break;
    case '(':
      if (syntax & RE_NO_BK_PARENS)
	token->type = OP_OPEN_SUBEXP;
      break;
    case ')':
      if (syntax & RE_NO_BK_PARENS)
	token->type = OP_CLOSE_SUBEXP;
      break;
    case '[':
      token->type = OP_OPEN_BRACKET;
      break;
    case '.':
      token->type = OP_PERIOD;
      break;
    case '^':
      if (!(syntax & (RE_CONTEXT_INDEP_ANCHORS | RE_CARET_ANCHORS_HERE)) &&
	  re_string_cur_idx (input) != 0)
	{
	  char prev = re_string_peek_byte (input, -1);
	  if (!(syntax & RE_NEWLINE_ALT) || prev != '\n')
	    break;
	}
      token->type = ANCHOR;
      token->opr.ctx_type = LINE_FIRST;
      break;
    case '$':
      if (!(syntax & RE_CONTEXT_INDEP_ANCHORS) &&
	  re_string_cur_idx (input) + 1 != re_string_length (input))
	{
	  re_token_t next;
	  re_string_skip_bytes (input, 1);
	  peek_token (&next, input, syntax);
	  re_string_skip_bytes (input, -1);
	  if (next.type != OP_ALT && next.type != OP_CLOSE_SUBEXP)
	    break;
	}
      token->type = ANCHOR;
      token->opr.ctx_type = LINE_LAST;
      break;
    default:
      break;
    }
  return 1;
}

/* Peek a token from INPUT, and return the length of the token.
   We must not use this function out of bracket expressions.  */

static int
internal_function
peek_token_bracket (re_token_t *token, re_string_t *input, reg_syntax_t syntax)
{
  unsigned char c;
  if (re_string_eoi (input))
    {
      token->type = END_OF_RE;
      return 0;
    }
  c = re_string_peek_byte (input, 0);
  token->opr.c = c;

#ifdef RE_ENABLE_I18N
  if (input->mb_cur_max > 1 &&
      !re_string_first_byte (input, re_string_cur_idx (input)))
    {
      token->type = CHARACTER;
      return 1;
    }
#endif /* RE_ENABLE_I18N */

  if (c == '\\' && (syntax & RE_BACKSLASH_ESCAPE_IN_LISTS)
      && re_string_cur_idx (input) + 1 < re_string_length (input))
    {
      /* In this case, '\' escape a character.  */
      unsigned char c2;
      re_string_skip_bytes (input, 1);
      c2 = re_string_peek_byte (input, 0);
      token->opr.c = c2;
      token->type = CHARACTER;
      return 1;
    }
  if (c == '[') /* '[' is a special char in a bracket exps.  */
    {
      unsigned char c2;
      int token_len;
      if (re_string_cur_idx (input) + 1 < re_string_length (input))
	c2 = re_string_peek_byte (input, 1);
      else
	c2 = 0;
      token->opr.c = c2;
      token_len = 2;
      switch (c2)
	{
	case '.':
	  token->type = OP_OPEN_COLL_ELEM;
	  break;
	case '=':
	  token->type = OP_OPEN_EQUIV_CLASS;
	  break;
	case ':':
	  if (syntax & RE_CHAR_CLASSES)
	    {
	      token->type = OP_OPEN_CHAR_CLASS;
	      break;
	    }
	  /* else fall through.  */
	default:
	  token->type = CHARACTER;
	  token->opr.c = c;
	  token_len = 1;
	  break;
	}
      return token_len;
    }
  switch (c)
    {
    case '-':
      token->type = OP_CHARSET_RANGE;
      break;
    case ']':
      token->type = OP_CLOSE_BRACKET;
      break;
    case '^':
      token->type = OP_NON_MATCH_LIST;
      break;
    default:
      token->type = CHARACTER;
    }
  return 1;
}

/* Functions for parser.  */

/* Entry point of the parser.
   Parse the regular expression REGEXP and return the structure tree.
   If an error is occured, ERR is set by error code, and return NULL.
   This function build the following tree, from regular expression <reg_exp>:
	   CAT
	   / \
	  /   \
   <reg_exp>  EOR

   CAT means concatenation.
   EOR means end of regular expression.  */

static bin_tree_t *
parse (re_string_t *regexp, regex_t *preg, reg_syntax_t syntax,
       reg_errcode_t *err)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  bin_tree_t *tree, *eor, *root;
  re_token_t current_token;
  dfa->syntax = syntax;
  fetch_token (&current_token, regexp, syntax | RE_CARET_ANCHORS_HERE);
  tree = parse_reg_exp (regexp, preg, &current_token, syntax, 0, err);
  if (BE (*err != REG_NOERROR && tree == NULL, 0))
    return NULL;
  eor = create_tree (dfa, NULL, NULL, END_OF_RE);
  if (tree != NULL)
    root = create_tree (dfa, tree, eor, CONCAT);
  else
    root = eor;
  if (BE (eor == NULL || root == NULL, 0))
    {
      *err = REG_ESPACE;
      return NULL;
    }
  return root;
}

/* This function build the following tree, from regular expression
   <branch1>|<branch2>:
	   ALT
	   / \
	  /   \
   <branch1> <branch2>

   ALT means alternative, which represents the operator `|'.  */

static bin_tree_t *
parse_reg_exp (re_string_t *regexp, regex_t *preg, re_token_t *token,
	       reg_syntax_t syntax, int nest, reg_errcode_t *err)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  bin_tree_t *tree, *branch = NULL;
  tree = parse_branch (regexp, preg, token, syntax, nest, err);
  if (BE (*err != REG_NOERROR && tree == NULL, 0))
    return NULL;

  while (token->type == OP_ALT)
    {
      fetch_token (token, regexp, syntax | RE_CARET_ANCHORS_HERE);
      if (token->type != OP_ALT && token->type != END_OF_RE
	  && (nest == 0 || token->type != OP_CLOSE_SUBEXP))
	{
	  branch = parse_branch (regexp, preg, token, syntax, nest, err);
	  if (BE (*err != REG_NOERROR && branch == NULL, 0))
	    return NULL;
	}
      else
	branch = NULL;
      tree = create_tree (dfa, tree, branch, OP_ALT);
      if (BE (tree == NULL, 0))
	{
	  *err = REG_ESPACE;
	  return NULL;
	}
    }
  return tree;
}

/* This function build the following tree, from regular expression
   <exp1><exp2>:
	CAT
	/ \
       /   \
   <exp1> <exp2>

   CAT means concatenation.  */

static bin_tree_t *
parse_branch (re_string_t *regexp, regex_t *preg, re_token_t *token,
	      reg_syntax_t syntax, int nest, reg_errcode_t *err)
{
  bin_tree_t *tree, *exp;
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  tree = parse_expression (regexp, preg, token, syntax, nest, err);
  if (BE (*err != REG_NOERROR && tree == NULL, 0))
    return NULL;

  while (token->type != OP_ALT && token->type != END_OF_RE
	 && (nest == 0 || token->type != OP_CLOSE_SUBEXP))
    {
      exp = parse_expression (regexp, preg, token, syntax, nest, err);
      if (BE (*err != REG_NOERROR && exp == NULL, 0))
	{
	  return NULL;
	}
      if (tree != NULL && exp != NULL)
	{
	  tree = create_tree (dfa, tree, exp, CONCAT);
	  if (tree == NULL)
	    {
	      *err = REG_ESPACE;
	      return NULL;
	    }
	}
      else if (tree == NULL)
	tree = exp;
      /* Otherwise exp == NULL, we don't need to create new tree.  */
    }
  return tree;
}

/* This function build the following tree, from regular expression a*:
	 *
	 |
	 a
*/

static bin_tree_t *
parse_expression (re_string_t *regexp, regex_t *preg, re_token_t *token,
		  reg_syntax_t syntax, int nest, reg_errcode_t *err)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  bin_tree_t *tree;
  switch (token->type)
    {
    case CHARACTER:
      tree = create_token_tree (dfa, NULL, NULL, token);
      if (BE (tree == NULL, 0))
	{
	  *err = REG_ESPACE;
	  return NULL;
	}
#ifdef RE_ENABLE_I18N
      if (dfa->mb_cur_max > 1)
	{
	  while (!re_string_eoi (regexp)
		 && !re_string_first_byte (regexp, re_string_cur_idx (regexp)))
	    {
	      bin_tree_t *mbc_remain;
	      fetch_token (token, regexp, syntax);
	      mbc_remain = create_token_tree (dfa, NULL, NULL, token);
	      tree = create_tree (dfa, tree, mbc_remain, CONCAT);
	      if (BE (mbc_remain == NULL || tree == NULL, 0))
		{
		  *err = REG_ESPACE;
		  return NULL;
		}
	    }
	}
#endif
      break;
    case OP_OPEN_SUBEXP:
      tree = parse_sub_exp (regexp, preg, token, syntax, nest + 1, err);
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
	return NULL;
      break;
    case OP_OPEN_BRACKET:
      tree = parse_bracket_exp (regexp, dfa, token, syntax, err);
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
	return NULL;
      break;
    case OP_BACK_REF:
      if (!BE (dfa->completed_bkref_map & (1 << token->opr.idx), 1))
	{
	  *err = REG_ESUBREG;
	  return NULL;
	}
      dfa->used_bkref_map |= 1 << token->opr.idx;
      tree = create_token_tree (dfa, NULL, NULL, token);
      if (BE (tree == NULL, 0))
	{
	  *err = REG_ESPACE;
	  return NULL;
	}
      ++dfa->nbackref;
      dfa->has_mb_node = 1;
      break;
    case OP_OPEN_DUP_NUM:
      if (syntax & RE_CONTEXT_INVALID_DUP)
	{
	  *err = REG_BADRPT;
	  return NULL;
	}
      /* FALLTHROUGH */
    case OP_DUP_ASTERISK:
    case OP_DUP_PLUS:
    case OP_DUP_QUESTION:
      if (syntax & RE_CONTEXT_INVALID_OPS)
	{
	  *err = REG_BADRPT;
	  return NULL;
	}
      else if (syntax & RE_CONTEXT_INDEP_OPS)
	{
	  fetch_token (token, regexp, syntax);
	  return parse_expression (regexp, preg, token, syntax, nest, err);
	}
      /* else fall through  */
    case OP_CLOSE_SUBEXP:
      if ((token->type == OP_CLOSE_SUBEXP) &&
	  !(syntax & RE_UNMATCHED_RIGHT_PAREN_ORD))
	{
	  *err = REG_ERPAREN;
	  return NULL;
	}
      /* else fall through  */
    case OP_CLOSE_DUP_NUM:
      /* We treat it as a normal character.  */

      /* Then we can these characters as normal characters.  */
      token->type = CHARACTER;
      /* mb_partial and word_char bits should be initialized already
	 by peek_token.  */
      tree = create_token_tree (dfa, NULL, NULL, token);
      if (BE (tree == NULL, 0))
	{
	  *err = REG_ESPACE;
	  return NULL;
	}
      break;
    case ANCHOR:
      if ((token->opr.ctx_type
	   & (WORD_DELIM | NOT_WORD_DELIM | WORD_FIRST | WORD_LAST))
	  && dfa->word_ops_used == 0)
	init_word_char (dfa);
      if (token->opr.ctx_type == WORD_DELIM
	  || token->opr.ctx_type == NOT_WORD_DELIM)
	{
	  bin_tree_t *tree_first, *tree_last;
	  if (token->opr.ctx_type == WORD_DELIM)
	    {
	      token->opr.ctx_type = WORD_FIRST;
	      tree_first = create_token_tree (dfa, NULL, NULL, token);
	      token->opr.ctx_type = WORD_LAST;
	    }
	  else
	    {
	      token->opr.ctx_type = INSIDE_WORD;
	      tree_first = create_token_tree (dfa, NULL, NULL, token);
	      token->opr.ctx_type = INSIDE_NOTWORD;
	    }
	  tree_last = create_token_tree (dfa, NULL, NULL, token);
	  tree = create_tree (dfa, tree_first, tree_last, OP_ALT);
	  if (BE (tree_first == NULL || tree_last == NULL || tree == NULL, 0))
	    {
	      *err = REG_ESPACE;
	      return NULL;
	    }
	}
      else
	{
	  tree = create_token_tree (dfa, NULL, NULL, token);
	  if (BE (tree == NULL, 0))
	    {
	      *err = REG_ESPACE;
	      return NULL;
	    }
	}
      /* We must return here, since ANCHORs can't be followed
	 by repetition operators.
	 eg. RE"^*" is invalid or "<ANCHOR(^)><CHAR(*)>",
	     it must not be "<ANCHOR(^)><REPEAT(*)>".  */
      fetch_token (token, regexp, syntax);
      return tree;
    case OP_PERIOD:
      tree = create_token_tree (dfa, NULL, NULL, token);
      if (BE (tree == NULL, 0))
	{
	  *err = REG_ESPACE;
	  return NULL;
	}
      if (dfa->mb_cur_max > 1)
	dfa->has_mb_node = 1;
      break;
    case OP_WORD:
    case OP_NOTWORD:
      tree = build_charclass_op (dfa, regexp->trans,
				 "alnum",
				 "_",
				 token->type == OP_NOTWORD, err);
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
	return NULL;
      break;
    case OP_SPACE:
    case OP_NOTSPACE:
      tree = build_charclass_op (dfa, regexp->trans,
				 "space",
				 "",
				 token->type == OP_NOTSPACE, err);
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
	return NULL;
      break;
    case OP_ALT:
    case END_OF_RE:
      return NULL;
    case BACK_SLASH:
      *err = REG_EESCAPE;
      return NULL;
    default:
      /* Must not happen?  */
#ifdef DEBUG
      assert (0);
#endif
      return NULL;
    }
  fetch_token (token, regexp, syntax);

  while (token->type == OP_DUP_ASTERISK || token->type == OP_DUP_PLUS
	 || token->type == OP_DUP_QUESTION || token->type == OP_OPEN_DUP_NUM)
    {
      tree = parse_dup_op (tree, regexp, dfa, token, syntax, err);
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
	return NULL;
      /* In BRE consecutive duplications are not allowed.  */
      if ((syntax & RE_CONTEXT_INVALID_DUP)
	  && (token->type == OP_DUP_ASTERISK
	      || token->type == OP_OPEN_DUP_NUM))
	{
	  *err = REG_BADRPT;
	  return NULL;
	}
    }

  return tree;
}

/* This function build the following tree, from regular expression
   (<reg_exp>):
	 SUBEXP
	    |
	<reg_exp>
*/

static bin_tree_t *
parse_sub_exp (re_string_t *regexp, regex_t *preg, re_token_t *token,
	       reg_syntax_t syntax, int nest, reg_errcode_t *err)
{
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  bin_tree_t *tree;
  size_t cur_nsub;
  cur_nsub = preg->re_nsub++;

  fetch_token (token, regexp, syntax | RE_CARET_ANCHORS_HERE);

  /* The subexpression may be a null string.  */
  if (token->type == OP_CLOSE_SUBEXP)
    tree = NULL;
  else
    {
      tree = parse_reg_exp (regexp, preg, token, syntax, nest, err);
      if (BE (*err == REG_NOERROR && token->type != OP_CLOSE_SUBEXP, 0))
	*err = REG_EPAREN;
      if (BE (*err != REG_NOERROR, 0))
	return NULL;
    }

  if (cur_nsub <= '9' - '1')
    dfa->completed_bkref_map |= 1 << cur_nsub;

  tree = create_tree (dfa, tree, NULL, SUBEXP);
  if (BE (tree == NULL, 0))
    {
      *err = REG_ESPACE;
      return NULL;
    }
  tree->token.opr.idx = cur_nsub;
  return tree;
}

/* This function parse repetition operators like "*", "+", "{1,3}" etc.  */

static bin_tree_t *
parse_dup_op (bin_tree_t *elem, re_string_t *regexp, re_dfa_t *dfa,
	      re_token_t *token, reg_syntax_t syntax, reg_errcode_t *err)
{
  bin_tree_t *tree = NULL, *old_tree = NULL;
  int i, start, end, start_idx = re_string_cur_idx (regexp);
#ifndef RE_TOKEN_INIT_BUG
  re_token_t start_token = *token;
#else
  re_token_t start_token;

  memcpy ((void *) &start_token, (void *) token, sizeof start_token);
#endif

  if (token->type == OP_OPEN_DUP_NUM)
    {
      end = 0;
      start = fetch_number (regexp, token, syntax);
      if (start == -1)
	{
	  if (token->type == CHARACTER && token->opr.c == ',')
	    start = 0; /* We treat "{,m}" as "{0,m}".  */
	  else
	    {
	      *err = REG_BADBR; /* <re>{} is invalid.  */
	      return NULL;
	    }
	}
      if (BE (start != -2, 1))
	{
	  /* We treat "{n}" as "{n,n}".  */
	  end = ((token->type == OP_CLOSE_DUP_NUM) ? start
		 : ((token->type == CHARACTER && token->opr.c == ',')
		    ? fetch_number (regexp, token, syntax) : -2));
	}
      if (BE (start == -2 || end == -2, 0))
	{
	  /* Invalid sequence.  */
	  if (BE (!(syntax & RE_INVALID_INTERVAL_ORD), 0))
	    {
	      if (token->type == END_OF_RE)
		*err = REG_EBRACE;
	      else
		*err = REG_BADBR;

	      return NULL;
	    }

	  /* If the syntax bit is set, rollback.  */
	  re_string_set_index (regexp, start_idx);
	  *token = start_token;
	  token->type = CHARACTER;
	  /* mb_partial and word_char bits should be already initialized by
	     peek_token.  */
	  return elem;
	}

      if (BE ((end != -1 && start > end) || token->type != OP_CLOSE_DUP_NUM, 0))
	{
	  /* First number greater than second.  */
	  *err = REG_BADBR;
	  return NULL;
	}
    }
  else
    {
      start = (token->type == OP_DUP_PLUS) ? 1 : 0;
      end = (token->type == OP_DUP_QUESTION) ? 1 : -1;
    }

  fetch_token (token, regexp, syntax);

  if (BE (elem == NULL, 0))
    return NULL;
  if (BE (start == 0 && end == 0, 0))
    {
      postorder (elem, free_tree, NULL);
      return NULL;
    }

  /* Extract "<re>{n,m}" to "<re><re>...<re><re>{0,<m-n>}".  */
  if (BE (start > 0, 0))
    {
      tree = elem;
      for (i = 2; i <= start; ++i)
	{
	  elem = duplicate_tree (elem, dfa);
	  tree = create_tree (dfa, tree, elem, CONCAT);
	  if (BE (elem == NULL || tree == NULL, 0))
	    goto parse_dup_op_espace;
	}

      if (start == end)
	return tree;

      /* Duplicate ELEM before it is marked optional.  */
      elem = duplicate_tree (elem, dfa);
      old_tree = tree;
    }
  else
    old_tree = NULL;

  if (elem->token.type == SUBEXP)
    postorder (elem, mark_opt_subexp, (void *) (long) elem->token.opr.idx);

  tree = create_tree (dfa, elem, NULL, (end == -1 ? OP_DUP_ASTERISK : OP_ALT));
  if (BE (tree == NULL, 0))
    goto parse_dup_op_espace;

  /* This loop is actually executed only when end != -1,
     to rewrite <re>{0,n} as (<re>(<re>...<re>?)?)?...  We have
     already created the start+1-th copy.  */
  for (i = start + 2; i <= end; ++i)
    {
      elem = duplicate_tree (elem, dfa);
      tree = create_tree (dfa, tree, elem, CONCAT);
      if (BE (elem == NULL || tree == NULL, 0))
	goto parse_dup_op_espace;

      tree = create_tree (dfa, tree, NULL, OP_ALT);
      if (BE (tree == NULL, 0))
	goto parse_dup_op_espace;
    }

  if (old_tree)
    tree = create_tree (dfa, old_tree, tree, CONCAT);

  return tree;

 parse_dup_op_espace:
  *err = REG_ESPACE;
  return NULL;
}

/* Size of the names for collating symbol/equivalence_class/character_class.
   I'm not sure, but maybe enough.  */
#define BRACKET_NAME_BUF_SIZE 32

#ifndef _LIBC
  /* Local function for parse_bracket_exp only used in case of NOT _LIBC.
     Build the range expression which starts from START_ELEM, and ends
     at END_ELEM.  The result are written to MBCSET and SBCSET.
     RANGE_ALLOC is the allocated size of mbcset->range_starts, and
     mbcset->range_ends, is a pointer argument sinse we may
     update it.  */

static reg_errcode_t
internal_function
# ifdef RE_ENABLE_I18N
build_range_exp (bitset_t sbcset, re_charset_t *mbcset, int *range_alloc,
		 bracket_elem_t *start_elem, bracket_elem_t *end_elem)
# else /* not RE_ENABLE_I18N */
build_range_exp (bitset_t sbcset, bracket_elem_t *start_elem,
		 bracket_elem_t *end_elem)
# endif /* not RE_ENABLE_I18N */
{
  unsigned int start_ch, end_ch;
  /* Equivalence Classes and Character Classes can't be a range start/end.  */
  if (BE (start_elem->type == EQUIV_CLASS || start_elem->type == CHAR_CLASS
	  || end_elem->type == EQUIV_CLASS || end_elem->type == CHAR_CLASS,
	  0))
    return REG_ERANGE;

  /* We can handle no multi character collating elements without libc
     support.  */
  if (BE ((start_elem->type == COLL_SYM
	   && strlen ((char *) start_elem->opr.name) > 1)
	  || (end_elem->type == COLL_SYM
	      && strlen ((char *) end_elem->opr.name) > 1), 0))
    return REG_ECOLLATE;

# ifdef RE_ENABLE_I18N
  {
    wchar_t wc;
    wint_t start_wc;
    wint_t end_wc;
    wchar_t cmp_buf[6] = {L'\0', L'\0', L'\0', L'\0', L'\0', L'\0'};

    start_ch = ((start_elem->type == SB_CHAR) ? start_elem->opr.ch
		: ((start_elem->type == COLL_SYM) ? start_elem->opr.name[0]
		   : 0));
    end_ch = ((end_elem->type == SB_CHAR) ? end_elem->opr.ch
	      : ((end_elem->type == COLL_SYM) ? end_elem->opr.name[0]
		 : 0));
#ifdef GAWK
    /*
     * Fedora Core 2, maybe others, have broken `btowc' that returns -1
     * for any value > 127. Sigh. Note that `start_ch' and `end_ch' are
     * unsigned, so we don't have sign extension problems.
     */
    start_wc = ((start_elem->type == SB_CHAR || start_elem->type == COLL_SYM)
		? start_ch : start_elem->opr.wch);
    end_wc = ((end_elem->type == SB_CHAR || end_elem->type == COLL_SYM)
	      ? end_ch : end_elem->opr.wch);
#else
    start_wc = ((start_elem->type == SB_CHAR || start_elem->type == COLL_SYM)
		? __btowc (start_ch) : start_elem->opr.wch);
    end_wc = ((end_elem->type == SB_CHAR || end_elem->type == COLL_SYM)
	      ? __btowc (end_ch) : end_elem->opr.wch);
#endif
    if (start_wc == WEOF || end_wc == WEOF)
      return REG_ECOLLATE;
    cmp_buf[0] = start_wc;
    cmp_buf[4] = end_wc;
    if (wcscoll (cmp_buf, cmp_buf + 4) > 0)
      return REG_ERANGE;

    /* Got valid collation sequence values, add them as a new entry.
       However, for !_LIBC we have no collation elements: if the
       character set is single byte, the single byte character set
       that we build below suffices.  parse_bracket_exp passes
       no MBCSET if dfa->mb_cur_max == 1.  */
    if (mbcset)
      {
	/* Check the space of the arrays.  */
	if (BE (*range_alloc == mbcset->nranges, 0))
	  {
	    /* There is not enough space, need realloc.  */
	    wchar_t *new_array_start, *new_array_end;
	    int new_nranges;

	    /* +1 in case of mbcset->nranges is 0.  */
	    new_nranges = 2 * mbcset->nranges + 1;
	    /* Use realloc since mbcset->range_starts and mbcset->range_ends
	       are NULL if *range_alloc == 0.  */
	    new_array_start = re_realloc (mbcset->range_starts, wchar_t,
					  new_nranges);
	    new_array_end = re_realloc (mbcset->range_ends, wchar_t,
					new_nranges);

	    if (BE (new_array_start == NULL || new_array_end == NULL, 0))
	      return REG_ESPACE;

	    mbcset->range_starts = new_array_start;
	    mbcset->range_ends = new_array_end;
	    *range_alloc = new_nranges;
	  }

	mbcset->range_starts[mbcset->nranges] = start_wc;
	mbcset->range_ends[mbcset->nranges++] = end_wc;
      }

    /* Build the table for single byte characters.  */
    for (wc = 0; wc < SBC_MAX; ++wc)
      {
	cmp_buf[2] = wc;
	if (wcscoll (cmp_buf, cmp_buf + 2) <= 0
	    && wcscoll (cmp_buf + 2, cmp_buf + 4) <= 0)
	  bitset_set (sbcset, wc);
      }
  }
# else /* not RE_ENABLE_I18N */
  {
    unsigned int ch;
    start_ch = ((start_elem->type == SB_CHAR ) ? start_elem->opr.ch
		: ((start_elem->type == COLL_SYM) ? start_elem->opr.name[0]
		   : 0));
    end_ch = ((end_elem->type == SB_CHAR ) ? end_elem->opr.ch
	      : ((end_elem->type == COLL_SYM) ? end_elem->opr.name[0]
		 : 0));
    if (start_ch > end_ch)
      return REG_ERANGE;
    /* Build the table for single byte characters.  */
    for (ch = 0; ch < SBC_MAX; ++ch)
      if (start_ch <= ch  && ch <= end_ch)
	bitset_set (sbcset, ch);
  }
# endif /* not RE_ENABLE_I18N */
  return REG_NOERROR;
}
#endif /* not _LIBC */

#ifndef _LIBC
/* Helper function for parse_bracket_exp only used in case of NOT _LIBC..
   Build the collating element which is represented by NAME.
   The result are written to MBCSET and SBCSET.
   COLL_SYM_ALLOC is the allocated size of mbcset->coll_sym, is a
   pointer argument since we may update it.  */

static reg_errcode_t
internal_function
# ifdef RE_ENABLE_I18N
build_collating_symbol (bitset_t sbcset, re_charset_t *mbcset,
			int *coll_sym_alloc, const unsigned char *name)
# else /* not RE_ENABLE_I18N */
build_collating_symbol (bitset_t sbcset, const unsigned char *name)
# endif /* not RE_ENABLE_I18N */
{
  size_t name_len = strlen ((const char *) name);
  if (BE (name_len != 1, 0))
    return REG_ECOLLATE;
  else
    {
      bitset_set (sbcset, name[0]);
      return REG_NOERROR;
    }
}
#endif /* not _LIBC */

/* This function parse bracket expression like "[abc]", "[a-c]",
   "[[.a-a.]]" etc.  */

static bin_tree_t *
parse_bracket_exp (re_string_t *regexp, re_dfa_t *dfa, re_token_t *token,
		   reg_syntax_t syntax, reg_errcode_t *err)
{
#ifdef _LIBC
  const unsigned char *collseqmb;
  const char *collseqwc;
  uint32_t nrules;
  int32_t table_size;
  const int32_t *symb_table;
  const unsigned char *extra;

  /* Local function for parse_bracket_exp used in _LIBC environement.
     Seek the collating symbol entry correspondings to NAME.
     Return the index of the symbol in the SYMB_TABLE.  */

  auto inline int32_t
  __attribute ((always_inline))
  seek_collating_symbol_entry (name, name_len)
	 const unsigned char *name;
	 size_t name_len;
    {
      int32_t hash = elem_hash ((const char *) name, name_len);
      int32_t elem = hash % table_size;
      if (symb_table[2 * elem] != 0)
	{
	  int32_t second = hash % (table_size - 2) + 1;

	  do
	    {
	      /* First compare the hashing value.  */
	      if (symb_table[2 * elem] == hash
		  /* Compare the length of the name.  */
		  && name_len == extra[symb_table[2 * elem + 1]]
		  /* Compare the name.  */
		  && memcmp (name, &extra[symb_table[2 * elem + 1] + 1],
			     name_len) == 0)
		{
		  /* Yep, this is the entry.  */
		  break;
		}

	      /* Next entry.  */
	      elem += second;
	    }
	  while (symb_table[2 * elem] != 0);
	}
      return elem;
    }

  /* Local function for parse_bracket_exp used in _LIBC environment.
     Look up the collation sequence value of BR_ELEM.
     Return the value if succeeded, UINT_MAX otherwise.  */

  auto inline unsigned int
  __attribute ((always_inline))
  lookup_collation_sequence_value (br_elem)
	 bracket_elem_t *br_elem;
    {
      if (br_elem->type == SB_CHAR)
	{
	  /*
	  if (MB_CUR_MAX == 1)
	  */
	  if (nrules == 0)
	    return collseqmb[br_elem->opr.ch];
	  else
	    {
	      wint_t wc = __btowc (br_elem->opr.ch);
	      return __collseq_table_lookup (collseqwc, wc);
	    }
	}
      else if (br_elem->type == MB_CHAR)
	{
	  if (nrules != 0)
	    return __collseq_table_lookup (collseqwc, br_elem->opr.wch);
	}
      else if (br_elem->type == COLL_SYM)
	{
	  size_t sym_name_len = strlen ((char *) br_elem->opr.name);
	  if (nrules != 0)
	    {
	      int32_t elem, idx;
	      elem = seek_collating_symbol_entry (br_elem->opr.name,
						  sym_name_len);
	      if (symb_table[2 * elem] != 0)
		{
		  /* We found the entry.  */
		  idx = symb_table[2 * elem + 1];
		  /* Skip the name of collating element name.  */
		  idx += 1 + extra[idx];
		  /* Skip the byte sequence of the collating element.  */
		  idx += 1 + extra[idx];
		  /* Adjust for the alignment.  */
		  idx = (idx + 3) & ~3;
		  /* Skip the multibyte collation sequence value.  */
		  idx += sizeof (unsigned int);
		  /* Skip the wide char sequence of the collating element.  */
		  idx += sizeof (unsigned int) *
		    (1 + *(unsigned int *) (extra + idx));
		  /* Return the collation sequence value.  */
		  return *(unsigned int *) (extra + idx);
		}
	      else if (symb_table[2 * elem] == 0 && sym_name_len == 1)
		{
		  /* No valid character.  Match it as a single byte
		     character.  */
		  return collseqmb[br_elem->opr.name[0]];
		}
	    }
	  else if (sym_name_len == 1)
	    return collseqmb[br_elem->opr.name[0]];
	}
      return UINT_MAX;
    }

  /* Local function for parse_bracket_exp used in _LIBC environement.
     Build the range expression which starts from START_ELEM, and ends
     at END_ELEM.  The result are written to MBCSET and SBCSET.
     RANGE_ALLOC is the allocated size of mbcset->range_starts, and
     mbcset->range_ends, is a pointer argument sinse we may
     update it.  */

  auto inline reg_errcode_t
  __attribute ((always_inline))
  build_range_exp (sbcset, mbcset, range_alloc, start_elem, end_elem)
	 re_charset_t *mbcset;
	 int *range_alloc;
	 bitset_t sbcset;
	 bracket_elem_t *start_elem, *end_elem;
    {
      unsigned int ch;
      uint32_t start_collseq;
      uint32_t end_collseq;

      /* Equivalence Classes and Character Classes can't be a range
	 start/end.  */
      if (BE (start_elem->type == EQUIV_CLASS || start_elem->type == CHAR_CLASS
	      || end_elem->type == EQUIV_CLASS || end_elem->type == CHAR_CLASS,
	      0))
	return REG_ERANGE;

      start_collseq = lookup_collation_sequence_value (start_elem);
      end_collseq = lookup_collation_sequence_value (end_elem);
      /* Check start/end collation sequence values.  */
      if (BE (start_collseq == UINT_MAX || end_collseq == UINT_MAX, 0))
	return REG_ECOLLATE;
      if (BE ((syntax & RE_NO_EMPTY_RANGES) && start_collseq > end_collseq, 0))
	return REG_ERANGE;

      /* Got valid collation sequence values, add them as a new entry.
	 However, if we have no collation elements, and the character set
	 is single byte, the single byte character set that we
	 build below suffices. */
      if (nrules > 0 || dfa->mb_cur_max > 1)
	{
	  /* Check the space of the arrays.  */
	  if (BE (*range_alloc == mbcset->nranges, 0))
	    {
	      /* There is not enough space, need realloc.  */
	      uint32_t *new_array_start;
	      uint32_t *new_array_end;
	      int new_nranges;

	      /* +1 in case of mbcset->nranges is 0.  */
	      new_nranges = 2 * mbcset->nranges + 1;
	      new_array_start = re_realloc (mbcset->range_starts, uint32_t,
					    new_nranges);
	      new_array_end = re_realloc (mbcset->range_ends, uint32_t,
					  new_nranges);

	      if (BE (new_array_start == NULL || new_array_end == NULL, 0))
		return REG_ESPACE;

	      mbcset->range_starts = new_array_start;
	      mbcset->range_ends = new_array_end;
	      *range_alloc = new_nranges;
	    }

	  mbcset->range_starts[mbcset->nranges] = start_collseq;
	  mbcset->range_ends[mbcset->nranges++] = end_collseq;
	}

      /* Build the table for single byte characters.  */
      for (ch = 0; ch < SBC_MAX; ch++)
	{
	  uint32_t ch_collseq;
	  /*
	  if (MB_CUR_MAX == 1)
	  */
	  if (nrules == 0)
	    ch_collseq = collseqmb[ch];
	  else
	    ch_collseq = __collseq_table_lookup (collseqwc, __btowc (ch));
	  if (start_collseq <= ch_collseq && ch_collseq <= end_collseq)
	    bitset_set (sbcset, ch);
	}
      return REG_NOERROR;
    }

  /* Local function for parse_bracket_exp used in _LIBC environement.
     Build the collating element which is represented by NAME.
     The result are written to MBCSET and SBCSET.
     COLL_SYM_ALLOC is the allocated size of mbcset->coll_sym, is a
     pointer argument sinse we may update it.  */

  auto inline reg_errcode_t
  __attribute ((always_inline))
  build_collating_symbol (sbcset, mbcset, coll_sym_alloc, name)
	 re_charset_t *mbcset;
	 int *coll_sym_alloc;
	 bitset_t sbcset;
	 const unsigned char *name;
    {
      int32_t elem, idx;
      size_t name_len = strlen ((const char *) name);
      if (nrules != 0)
	{
	  elem = seek_collating_symbol_entry (name, name_len);
	  if (symb_table[2 * elem] != 0)
	    {
	      /* We found the entry.  */
	      idx = symb_table[2 * elem + 1];
	      /* Skip the name of collating element name.  */
	      idx += 1 + extra[idx];
	    }
	  else if (symb_table[2 * elem] == 0 && name_len == 1)
	    {
	      /* No valid character, treat it as a normal
		 character.  */
	      bitset_set (sbcset, name[0]);
	      return REG_NOERROR;
	    }
	  else
	    return REG_ECOLLATE;

	  /* Got valid collation sequence, add it as a new entry.  */
	  /* Check the space of the arrays.  */
	  if (BE (*coll_sym_alloc == mbcset->ncoll_syms, 0))
	    {
	      /* Not enough, realloc it.  */
	      /* +1 in case of mbcset->ncoll_syms is 0.  */
	      int new_coll_sym_alloc = 2 * mbcset->ncoll_syms + 1;
	      /* Use realloc since mbcset->coll_syms is NULL
		 if *alloc == 0.  */
	      int32_t *new_coll_syms = re_realloc (mbcset->coll_syms, int32_t,
						   new_coll_sym_alloc);
	      if (BE (new_coll_syms == NULL, 0))
		return REG_ESPACE;
	      mbcset->coll_syms = new_coll_syms;
	      *coll_sym_alloc = new_coll_sym_alloc;
	    }
	  mbcset->coll_syms[mbcset->ncoll_syms++] = idx;
	  return REG_NOERROR;
	}
      else
	{
	  if (BE (name_len != 1, 0))
	    return REG_ECOLLATE;
	  else
	    {
	      bitset_set (sbcset, name[0]);
	      return REG_NOERROR;
	    }
	}
    }
#endif

  re_token_t br_token;
  re_bitset_ptr_t sbcset;
#ifdef RE_ENABLE_I18N
  re_charset_t *mbcset;
  int coll_sym_alloc = 0, range_alloc = 0, mbchar_alloc = 0;
  int equiv_class_alloc = 0, char_class_alloc = 0;
#endif /* not RE_ENABLE_I18N */
  int non_match = 0;
  bin_tree_t *work_tree;
  int token_len;
  int first_round = 1;
#ifdef _LIBC
  collseqmb = (const unsigned char *)
    _NL_CURRENT (LC_COLLATE, _NL_COLLATE_COLLSEQMB);
  nrules = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
  if (nrules)
    {
      /*
      if (MB_CUR_MAX > 1)
      */
      collseqwc = _NL_CURRENT (LC_COLLATE, _NL_COLLATE_COLLSEQWC);
      table_size = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_SYMB_HASH_SIZEMB);
      symb_table = (const int32_t *) _NL_CURRENT (LC_COLLATE,
						  _NL_COLLATE_SYMB_TABLEMB);
      extra = (const unsigned char *) _NL_CURRENT (LC_COLLATE,
						   _NL_COLLATE_SYMB_EXTRAMB);
    }
#endif
  sbcset = (re_bitset_ptr_t) calloc (sizeof (bitset_t), 1);
#ifdef RE_ENABLE_I18N
  mbcset = (re_charset_t *) calloc (sizeof (re_charset_t), 1);
#endif /* RE_ENABLE_I18N */
#ifdef RE_ENABLE_I18N
  if (BE (sbcset == NULL || mbcset == NULL, 0))
#else
  if (BE (sbcset == NULL, 0))
#endif /* RE_ENABLE_I18N */
    {
      *err = REG_ESPACE;
      return NULL;
    }

  token_len = peek_token_bracket (token, regexp, syntax);
  if (BE (token->type == END_OF_RE, 0))
    {
      *err = REG_BADPAT;
      goto parse_bracket_exp_free_return;
    }
  if (token->type == OP_NON_MATCH_LIST)
    {
#ifdef RE_ENABLE_I18N
      mbcset->non_match = 1;
#endif /* not RE_ENABLE_I18N */
      non_match = 1;
      if (syntax & RE_HAT_LISTS_NOT_NEWLINE)
	bitset_set (sbcset, '\n');
      re_string_skip_bytes (regexp, token_len); /* Skip a token.  */
      token_len = peek_token_bracket (token, regexp, syntax);
      if (BE (token->type == END_OF_RE, 0))
	{
	  *err = REG_BADPAT;
	  goto parse_bracket_exp_free_return;
	}
    }

  /* We treat the first ']' as a normal character.  */
  if (token->type == OP_CLOSE_BRACKET)
    token->type = CHARACTER;

  while (1)
    {
      bracket_elem_t start_elem, end_elem;
      unsigned char start_name_buf[BRACKET_NAME_BUF_SIZE];
      unsigned char end_name_buf[BRACKET_NAME_BUF_SIZE];
      reg_errcode_t ret;
      int token_len2 = 0, is_range_exp = 0;
      re_token_t token2;

      start_elem.opr.name = start_name_buf;
      ret = parse_bracket_element (&start_elem, regexp, token, token_len, dfa,
				   syntax, first_round);
      if (BE (ret != REG_NOERROR, 0))
	{
	  *err = ret;
	  goto parse_bracket_exp_free_return;
	}
      first_round = 0;

      /* Get information about the next token.  We need it in any case.  */
      token_len = peek_token_bracket (token, regexp, syntax);

      /* Do not check for ranges if we know they are not allowed.  */
      if (start_elem.type != CHAR_CLASS && start_elem.type != EQUIV_CLASS)
	{
	  if (BE (token->type == END_OF_RE, 0))
	    {
	      *err = REG_EBRACK;
	      goto parse_bracket_exp_free_return;
	    }
	  if (token->type == OP_CHARSET_RANGE)
	    {
	      re_string_skip_bytes (regexp, token_len); /* Skip '-'.  */
	      token_len2 = peek_token_bracket (&token2, regexp, syntax);
	      if (BE (token2.type == END_OF_RE, 0))
		{
		  *err = REG_EBRACK;
		  goto parse_bracket_exp_free_return;
		}
	      if (token2.type == OP_CLOSE_BRACKET)
		{
		  /* We treat the last '-' as a normal character.  */
		  re_string_skip_bytes (regexp, -token_len);
		  token->type = CHARACTER;
		}
	      else
		is_range_exp = 1;
	    }
	}

      if (is_range_exp == 1)
	{
	  end_elem.opr.name = end_name_buf;
	  ret = parse_bracket_element (&end_elem, regexp, &token2, token_len2,
				       dfa, syntax, 1);
	  if (BE (ret != REG_NOERROR, 0))
	    {
	      *err = ret;
	      goto parse_bracket_exp_free_return;
	    }

	  token_len = peek_token_bracket (token, regexp, syntax);

#ifdef _LIBC
	  *err = build_range_exp (sbcset, mbcset, &range_alloc,
				  &start_elem, &end_elem);
#else
# ifdef RE_ENABLE_I18N
	  *err = build_range_exp (sbcset,
				  dfa->mb_cur_max > 1 ? mbcset : NULL,
				  &range_alloc, &start_elem, &end_elem);
# else
	  *err = build_range_exp (sbcset, &start_elem, &end_elem);
# endif
#endif /* RE_ENABLE_I18N */
	  if (BE (*err != REG_NOERROR, 0))
	    goto parse_bracket_exp_free_return;
	}
      else
	{
	  switch (start_elem.type)
	    {
	    case SB_CHAR:
	      bitset_set (sbcset, start_elem.opr.ch);
	      break;
#ifdef RE_ENABLE_I18N
	    case MB_CHAR:
	      /* Check whether the array has enough space.  */
	      if (BE (mbchar_alloc == mbcset->nmbchars, 0))
		{
		  wchar_t *new_mbchars;
		  /* Not enough, realloc it.  */
		  /* +1 in case of mbcset->nmbchars is 0.  */
		  mbchar_alloc = 2 * mbcset->nmbchars + 1;
		  /* Use realloc since array is NULL if *alloc == 0.  */
		  new_mbchars = re_realloc (mbcset->mbchars, wchar_t,
					    mbchar_alloc);
		  if (BE (new_mbchars == NULL, 0))
		    goto parse_bracket_exp_espace;
		  mbcset->mbchars = new_mbchars;
		}
	      mbcset->mbchars[mbcset->nmbchars++] = start_elem.opr.wch;
	      break;
#endif /* RE_ENABLE_I18N */
	    case EQUIV_CLASS:
	      *err = build_equiv_class (sbcset,
#ifdef RE_ENABLE_I18N
					mbcset, &equiv_class_alloc,
#endif /* RE_ENABLE_I18N */
					start_elem.opr.name);
	      if (BE (*err != REG_NOERROR, 0))
		goto parse_bracket_exp_free_return;
	      break;
	    case COLL_SYM:
	      *err = build_collating_symbol (sbcset,
#ifdef RE_ENABLE_I18N
					     mbcset, &coll_sym_alloc,
#endif /* RE_ENABLE_I18N */
					     start_elem.opr.name);
	      if (BE (*err != REG_NOERROR, 0))
		goto parse_bracket_exp_free_return;
	      break;
	    case CHAR_CLASS:
	      *err = build_charclass (regexp->trans, sbcset,
#ifdef RE_ENABLE_I18N
				      mbcset, &char_class_alloc,
#endif /* RE_ENABLE_I18N */
				      (const char *) start_elem.opr.name, syntax);
	      if (BE (*err != REG_NOERROR, 0))
	       goto parse_bracket_exp_free_return;
	      break;
	    default:
	      assert (0);
	      break;
	    }
	}
      if (BE (token->type == END_OF_RE, 0))
	{
	  *err = REG_EBRACK;
	  goto parse_bracket_exp_free_return;
	}
      if (token->type == OP_CLOSE_BRACKET)
	break;
    }

  re_string_skip_bytes (regexp, token_len); /* Skip a token.  */

  /* If it is non-matching list.  */
  if (non_match)
    bitset_not (sbcset);

#ifdef RE_ENABLE_I18N
  /* Ensure only single byte characters are set.  */
  if (dfa->mb_cur_max > 1)
    bitset_mask (sbcset, dfa->sb_char);

  if (mbcset->nmbchars || mbcset->ncoll_syms || mbcset->nequiv_classes
      || mbcset->nranges || (dfa->mb_cur_max > 1 && (mbcset->nchar_classes
						     || mbcset->non_match)))
    {
      bin_tree_t *mbc_tree;
      int sbc_idx;
      /* Build a tree for complex bracket.  */
      dfa->has_mb_node = 1;
      br_token.type = COMPLEX_BRACKET;
      br_token.opr.mbcset = mbcset;
      mbc_tree = create_token_tree (dfa, NULL, NULL, &br_token);
      if (BE (mbc_tree == NULL, 0))
	goto parse_bracket_exp_espace;
      for (sbc_idx = 0; sbc_idx < BITSET_WORDS; ++sbc_idx)
	if (sbcset[sbc_idx])
	  break;
      /* If there are no bits set in sbcset, there is no point
	 of having both SIMPLE_BRACKET and COMPLEX_BRACKET.  */
      if (sbc_idx < BITSET_WORDS)
	{
	  /* Build a tree for simple bracket.  */
	  br_token.type = SIMPLE_BRACKET;
	  br_token.opr.sbcset = sbcset;
	  work_tree = create_token_tree (dfa, NULL, NULL, &br_token);
	  if (BE (work_tree == NULL, 0))
	    goto parse_bracket_exp_espace;

	  /* Then join them by ALT node.  */
	  work_tree = create_tree (dfa, work_tree, mbc_tree, OP_ALT);
	  if (BE (work_tree == NULL, 0))
	    goto parse_bracket_exp_espace;
	}
      else
	{
	  re_free (sbcset);
	  work_tree = mbc_tree;
	}
    }
  else
#endif /* not RE_ENABLE_I18N */
    {
#ifdef RE_ENABLE_I18N
      free_charset (mbcset);
#endif
      /* Build a tree for simple bracket.  */
      br_token.type = SIMPLE_BRACKET;
      br_token.opr.sbcset = sbcset;
      work_tree = create_token_tree (dfa, NULL, NULL, &br_token);
      if (BE (work_tree == NULL, 0))
	goto parse_bracket_exp_espace;
    }
  return work_tree;

 parse_bracket_exp_espace:
  *err = REG_ESPACE;
 parse_bracket_exp_free_return:
  re_free (sbcset);
#ifdef RE_ENABLE_I18N
  free_charset (mbcset);
#endif /* RE_ENABLE_I18N */
  return NULL;
}

/* Parse an element in the bracket expression.  */

static reg_errcode_t
parse_bracket_element (bracket_elem_t *elem, re_string_t *regexp,
		       re_token_t *token, int token_len, UNUSED re_dfa_t *dfa,
		       reg_syntax_t syntax, int accept_hyphen)
{
#ifdef RE_ENABLE_I18N
  int cur_char_size;
  cur_char_size = re_string_char_size_at (regexp, re_string_cur_idx (regexp));
  if (cur_char_size > 1)
    {
      elem->type = MB_CHAR;
      elem->opr.wch = re_string_wchar_at (regexp, re_string_cur_idx (regexp));
      re_string_skip_bytes (regexp, cur_char_size);
      return REG_NOERROR;
    }
#endif /* RE_ENABLE_I18N */
  re_string_skip_bytes (regexp, token_len); /* Skip a token.  */
  if (token->type == OP_OPEN_COLL_ELEM || token->type == OP_OPEN_CHAR_CLASS
      || token->type == OP_OPEN_EQUIV_CLASS)
    return parse_bracket_symbol (elem, regexp, token);
  if (BE (token->type == OP_CHARSET_RANGE, 0) && !accept_hyphen)
    {
      /* A '-' must only appear as anything but a range indicator before
	 the closing bracket.  Everything else is an error.  */
      re_token_t token2;
      (void) peek_token_bracket (&token2, regexp, syntax);
      if (token2.type != OP_CLOSE_BRACKET)
	/* The actual error value is not standardized since this whole
	   case is undefined.  But ERANGE makes good sense.  */
	return REG_ERANGE;
    }
  elem->type = SB_CHAR;
  elem->opr.ch = token->opr.c;
  return REG_NOERROR;
}

/* Parse a bracket symbol in the bracket expression.  Bracket symbols are
   such as [:<character_class>:], [.<collating_element>.], and
   [=<equivalent_class>=].  */

static reg_errcode_t
parse_bracket_symbol (bracket_elem_t *elem, re_string_t *regexp,
		      re_token_t *token)
{
  unsigned char ch, delim = token->opr.c;
  int i = 0;
  if (re_string_eoi(regexp))
    return REG_EBRACK;
  for (;; ++i)
    {
      if (i >= BRACKET_NAME_BUF_SIZE)
	return REG_EBRACK;
      if (token->type == OP_OPEN_CHAR_CLASS)
	ch = re_string_fetch_byte_case (regexp);
      else
	ch = re_string_fetch_byte (regexp);
      if (re_string_eoi(regexp))
	return REG_EBRACK;
      if (ch == delim && re_string_peek_byte (regexp, 0) == ']')
	break;
      elem->opr.name[i] = ch;
    }
  re_string_skip_bytes (regexp, 1);
  elem->opr.name[i] = '\0';
  switch (token->type)
    {
    case OP_OPEN_COLL_ELEM:
      elem->type = COLL_SYM;
      break;
    case OP_OPEN_EQUIV_CLASS:
      elem->type = EQUIV_CLASS;
      break;
    case OP_OPEN_CHAR_CLASS:
      elem->type = CHAR_CLASS;
      break;
    default:
      break;
    }
  return REG_NOERROR;
}

  /* Helper function for parse_bracket_exp.
     Build the equivalence class which is represented by NAME.
     The result are written to MBCSET and SBCSET.
     EQUIV_CLASS_ALLOC is the allocated size of mbcset->equiv_classes,
     is a pointer argument sinse we may update it.  */

static reg_errcode_t
#ifdef RE_ENABLE_I18N
build_equiv_class (bitset_t sbcset, re_charset_t *mbcset,
		   int *equiv_class_alloc, const unsigned char *name)
#else /* not RE_ENABLE_I18N */
build_equiv_class (bitset_t sbcset, const unsigned char *name)
#endif /* not RE_ENABLE_I18N */
{
#ifdef _LIBC
  uint32_t nrules = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
  if (nrules != 0)
    {
      const int32_t *table, *indirect;
      const unsigned char *weights, *extra, *cp;
      unsigned char char_buf[2];
      int32_t idx1, idx2;
      unsigned int ch;
      size_t len;
      /* This #include defines a local function!  */
# include <locale/weight.h>
      /* Calculate the index for equivalence class.  */
      cp = name;
      table = (const int32_t *) _NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEMB);
      weights = (const unsigned char *) _NL_CURRENT (LC_COLLATE,
					       _NL_COLLATE_WEIGHTMB);
      extra = (const unsigned char *) _NL_CURRENT (LC_COLLATE,
						   _NL_COLLATE_EXTRAMB);
      indirect = (const int32_t *) _NL_CURRENT (LC_COLLATE,
						_NL_COLLATE_INDIRECTMB);
      idx1 = findidx (&cp);
      if (BE (idx1 == 0 || cp < name + strlen ((const char *) name), 0))
	/* This isn't a valid character.  */
	return REG_ECOLLATE;

      /* Build single byte matcing table for this equivalence class.  */
      char_buf[1] = (unsigned char) '\0';
      len = weights[idx1 & 0xffffff];
      for (ch = 0; ch < SBC_MAX; ++ch)
	{
	  char_buf[0] = ch;
	  cp = char_buf;
	  idx2 = findidx (&cp);
/*
	  idx2 = table[ch];
*/
	  if (idx2 == 0)
	    /* This isn't a valid character.  */
	    continue;
	  /* Compare only if the length matches and the collation rule
	     index is the same.  */
	  if (len == weights[idx2 & 0xffffff] && (idx1 >> 24) == (idx2 >> 24))
	    {
	      int cnt = 0;

	      while (cnt <= len &&
		     weights[(idx1 & 0xffffff) + 1 + cnt]
		     == weights[(idx2 & 0xffffff) + 1 + cnt])
		++cnt;

	      if (cnt > len)
		bitset_set (sbcset, ch);
	    }
	}
      /* Check whether the array has enough space.  */
      if (BE (*equiv_class_alloc == mbcset->nequiv_classes, 0))
	{
	  /* Not enough, realloc it.  */
	  /* +1 in case of mbcset->nequiv_classes is 0.  */
	  int new_equiv_class_alloc = 2 * mbcset->nequiv_classes + 1;
	  /* Use realloc since the array is NULL if *alloc == 0.  */
	  int32_t *new_equiv_classes = re_realloc (mbcset->equiv_classes,
						   int32_t,
						   new_equiv_class_alloc);
	  if (BE (new_equiv_classes == NULL, 0))
	    return REG_ESPACE;
	  mbcset->equiv_classes = new_equiv_classes;
	  *equiv_class_alloc = new_equiv_class_alloc;
	}
      mbcset->equiv_classes[mbcset->nequiv_classes++] = idx1;
    }
  else
#endif /* _LIBC */
    {
      if (BE (strlen ((const char *) name) != 1, 0))
	return REG_ECOLLATE;
      bitset_set (sbcset, *name);
    }
  return REG_NOERROR;
}

  /* Helper function for parse_bracket_exp.
     Build the character class which is represented by NAME.
     The result are written to MBCSET and SBCSET.
     CHAR_CLASS_ALLOC is the allocated size of mbcset->char_classes,
     is a pointer argument sinse we may update it.  */

static reg_errcode_t
#ifdef RE_ENABLE_I18N
build_charclass (RE_TRANSLATE_TYPE trans, bitset_t sbcset,
		 re_charset_t *mbcset, int *char_class_alloc,
		 const char *class_name, reg_syntax_t syntax)
#else /* not RE_ENABLE_I18N */
build_charclass (RE_TRANSLATE_TYPE trans, bitset_t sbcset,
		 const char *class_name, reg_syntax_t syntax)
#endif /* not RE_ENABLE_I18N */
{
  int i;

  /* In case of REG_ICASE "upper" and "lower" match the both of
     upper and lower cases.  */
  if ((syntax & RE_ICASE)
      && (strcmp (class_name, "upper") == 0 || strcmp (class_name, "lower") == 0))
    class_name = "alpha";

#ifdef RE_ENABLE_I18N
  /* Check the space of the arrays.  */
  if (BE (*char_class_alloc == mbcset->nchar_classes, 0))
    {
      /* Not enough, realloc it.  */
      /* +1 in case of mbcset->nchar_classes is 0.  */
      int new_char_class_alloc = 2 * mbcset->nchar_classes + 1;
      /* Use realloc since array is NULL if *alloc == 0.  */
      wctype_t *new_char_classes = re_realloc (mbcset->char_classes, wctype_t,
					       new_char_class_alloc);
      if (BE (new_char_classes == NULL, 0))
	return REG_ESPACE;
      mbcset->char_classes = new_char_classes;
      *char_class_alloc = new_char_class_alloc;
    }
  mbcset->char_classes[mbcset->nchar_classes++] = __wctype (class_name);
#endif /* RE_ENABLE_I18N */

#define BUILD_CHARCLASS_LOOP(ctype_func)	\
  do {						\
    if (BE (trans != NULL, 0))			\
      {						\
	for (i = 0; i < SBC_MAX; ++i)		\
  	  if (ctype_func (i))			\
	    bitset_set (sbcset, trans[i]);	\
      }						\
    else					\
      {						\
	for (i = 0; i < SBC_MAX; ++i)		\
  	  if (ctype_func (i))			\
	    bitset_set (sbcset, i);		\
      }						\
  } while (0)

  if (strcmp (class_name, "alnum") == 0)
    BUILD_CHARCLASS_LOOP (isalnum);
  else if (strcmp (class_name, "cntrl") == 0)
    BUILD_CHARCLASS_LOOP (iscntrl);
  else if (strcmp (class_name, "lower") == 0)
    BUILD_CHARCLASS_LOOP (islower);
  else if (strcmp (class_name, "space") == 0)
    BUILD_CHARCLASS_LOOP (isspace);
  else if (strcmp (class_name, "alpha") == 0)
    BUILD_CHARCLASS_LOOP (isalpha);
  else if (strcmp (class_name, "digit") == 0)
    BUILD_CHARCLASS_LOOP (isdigit);
  else if (strcmp (class_name, "print") == 0)
    BUILD_CHARCLASS_LOOP (isprint);
  else if (strcmp (class_name, "upper") == 0)
    BUILD_CHARCLASS_LOOP (isupper);
  else if (strcmp (class_name, "blank") == 0)
#ifndef GAWK
    BUILD_CHARCLASS_LOOP (isblank);
#else
    /* see comments above */
    BUILD_CHARCLASS_LOOP (is_blank);
#endif
  else if (strcmp (class_name, "graph") == 0)
    BUILD_CHARCLASS_LOOP (isgraph);
  else if (strcmp (class_name, "punct") == 0)
    BUILD_CHARCLASS_LOOP (ispunct);
  else if (strcmp (class_name, "xdigit") == 0)
    BUILD_CHARCLASS_LOOP (isxdigit);
  else
    return REG_ECTYPE;

  return REG_NOERROR;
}

static bin_tree_t *
build_charclass_op (re_dfa_t *dfa, RE_TRANSLATE_TYPE trans,
		    const char *class_name,
		    const char *extra, int non_match,
		    reg_errcode_t *err)
{
  re_bitset_ptr_t sbcset;
#ifdef RE_ENABLE_I18N
  re_charset_t *mbcset;
  int alloc = 0;
#endif /* not RE_ENABLE_I18N */
  reg_errcode_t ret;
  re_token_t br_token;
  bin_tree_t *tree;

  sbcset = (re_bitset_ptr_t) calloc (sizeof (bitset_t), 1);
#ifdef RE_ENABLE_I18N
  mbcset = (re_charset_t *) calloc (sizeof (re_charset_t), 1);
#endif /* RE_ENABLE_I18N */

#ifdef RE_ENABLE_I18N
  if (BE (sbcset == NULL || mbcset == NULL, 0))
#else /* not RE_ENABLE_I18N */
  if (BE (sbcset == NULL, 0))
#endif /* not RE_ENABLE_I18N */
    {
      *err = REG_ESPACE;
      return NULL;
    }

  if (non_match)
    {
#ifdef RE_ENABLE_I18N
      mbcset->non_match = 1;
#endif /* not RE_ENABLE_I18N */
    }

  /* We don't care the syntax in this case.  */
  ret = build_charclass (trans, sbcset,
#ifdef RE_ENABLE_I18N
			 mbcset, &alloc,
#endif /* RE_ENABLE_I18N */
			 class_name, 0);

  if (BE (ret != REG_NOERROR, 0))
    {
      re_free (sbcset);
#ifdef RE_ENABLE_I18N
      free_charset (mbcset);
#endif /* RE_ENABLE_I18N */
      *err = ret;
      return NULL;
    }
  /* \w match '_' also.  */
  for (; *extra; extra++)
    bitset_set (sbcset, *extra);

  /* If it is non-matching list.  */
  if (non_match)
    bitset_not (sbcset);

#ifdef RE_ENABLE_I18N
  /* Ensure only single byte characters are set.  */
  if (dfa->mb_cur_max > 1)
    bitset_mask (sbcset, dfa->sb_char);
#endif

  /* Build a tree for simple bracket.  */
  br_token.type = SIMPLE_BRACKET;
  br_token.opr.sbcset = sbcset;
  tree = create_token_tree (dfa, NULL, NULL, &br_token);
  if (BE (tree == NULL, 0))
    goto build_word_op_espace;

#ifdef RE_ENABLE_I18N
  if (dfa->mb_cur_max > 1)
    {
      bin_tree_t *mbc_tree;
      /* Build a tree for complex bracket.  */
      br_token.type = COMPLEX_BRACKET;
      br_token.opr.mbcset = mbcset;
      dfa->has_mb_node = 1;
      mbc_tree = create_token_tree (dfa, NULL, NULL, &br_token);
      if (BE (mbc_tree == NULL, 0))
	goto build_word_op_espace;
      /* Then join them by ALT node.  */
      tree = create_tree (dfa, tree, mbc_tree, OP_ALT);
      if (BE (mbc_tree != NULL, 1))
	return tree;
    }
  else
    {
      free_charset (mbcset);
      return tree;
    }
#else /* not RE_ENABLE_I18N */
  return tree;
#endif /* not RE_ENABLE_I18N */

 build_word_op_espace:
  re_free (sbcset);
#ifdef RE_ENABLE_I18N
  free_charset (mbcset);
#endif /* RE_ENABLE_I18N */
  *err = REG_ESPACE;
  return NULL;
}

/* This is intended for the expressions like "a{1,3}".
   Fetch a number from `input', and return the number.
   Return -1, if the number field is empty like "{,1}".
   Return -2, If an error is occured.  */

static int
fetch_number (re_string_t *input, re_token_t *token, reg_syntax_t syntax)
{
  int num = -1;
  unsigned char c;
  while (1)
    {
      fetch_token (token, input, syntax);
      c = token->opr.c;
      if (BE (token->type == END_OF_RE, 0))
	return -2;
      if (token->type == OP_CLOSE_DUP_NUM || c == ',')
	break;
      num = ((token->type != CHARACTER || c < '0' || '9' < c || num == -2)
	     ? -2 : ((num == -1) ? c - '0' : num * 10 + c - '0'));
      num = (num > RE_DUP_MAX) ? -2 : num;
    }
  return num;
}

#ifdef RE_ENABLE_I18N
static void
free_charset (re_charset_t *cset)
{
  re_free (cset->mbchars);
# ifdef _LIBC
  re_free (cset->coll_syms);
  re_free (cset->equiv_classes);
  re_free (cset->range_starts);
  re_free (cset->range_ends);
# endif
  re_free (cset->char_classes);
  re_free (cset);
}
#endif /* RE_ENABLE_I18N */

/* Functions for binary tree operation.  */

/* Create a tree node.  */

static bin_tree_t *
create_tree (re_dfa_t *dfa, bin_tree_t *left, bin_tree_t *right,
	     re_token_type_t type)
{
  re_token_t t;
  t.type = type;
  return create_token_tree (dfa, left, right, &t);
}

static bin_tree_t *
create_token_tree (re_dfa_t *dfa, bin_tree_t *left, bin_tree_t *right,
		   const re_token_t *token)
{
  bin_tree_t *tree;
  if (BE (dfa->str_tree_storage_idx == BIN_TREE_STORAGE_SIZE, 0))
    {
      bin_tree_storage_t *storage = re_malloc (bin_tree_storage_t, 1);

      if (storage == NULL)
	return NULL;
      storage->next = dfa->str_tree_storage;
      dfa->str_tree_storage = storage;
      dfa->str_tree_storage_idx = 0;
    }
  tree = &dfa->str_tree_storage->data[dfa->str_tree_storage_idx++];

  tree->parent = NULL;
  tree->left = left;
  tree->right = right;
  tree->token = *token;
  tree->token.duplicated = 0;
  tree->token.opt_subexp = 0;
  tree->first = NULL;
  tree->next = NULL;
  tree->node_idx = -1;

  if (left != NULL)
    left->parent = tree;
  if (right != NULL)
    right->parent = tree;
  return tree;
}

/* Mark the tree SRC as an optional subexpression.
   To be called from preorder or postorder.  */

static reg_errcode_t
mark_opt_subexp (void *extra, bin_tree_t *node)
{
  int idx = (int) (long) extra;
  if (node->token.type == SUBEXP && node->token.opr.idx == idx)
    node->token.opt_subexp = 1;

  return REG_NOERROR;
}

/* Free the allocated memory inside NODE. */

static void
free_token (re_token_t *node)
{
#ifdef RE_ENABLE_I18N
  if (node->type == COMPLEX_BRACKET && node->duplicated == 0)
    free_charset (node->opr.mbcset);
  else
#endif /* RE_ENABLE_I18N */
    if (node->type == SIMPLE_BRACKET && node->duplicated == 0)
      re_free (node->opr.sbcset);
}

/* Worker function for tree walking.  Free the allocated memory inside NODE
   and its children. */

static reg_errcode_t
free_tree (UNUSED void *extra, bin_tree_t *node)
{
  free_token (&node->token);
  return REG_NOERROR;
}


/* Duplicate the node SRC, and return new node.  This is a preorder
   visit similar to the one implemented by the generic visitor, but
   we need more infrastructure to maintain two parallel trees --- so,
   it's easier to duplicate.  */

static bin_tree_t *
duplicate_tree (const bin_tree_t *root, re_dfa_t *dfa)
{
  const bin_tree_t *node;
  bin_tree_t *dup_root;
  bin_tree_t **p_new = &dup_root, *dup_node = root->parent;

  for (node = root; ; )
    {
      /* Create a new tree and link it back to the current parent.  */
      *p_new = create_token_tree (dfa, NULL, NULL, &node->token);
      if (*p_new == NULL)
	return NULL;
      (*p_new)->parent = dup_node;
      (*p_new)->token.duplicated = 1;
      dup_node = *p_new;

      /* Go to the left node, or up and to the right.  */
      if (node->left)
	{
	  node = node->left;
	  p_new = &dup_node->left;
	}
      else
	{
	  const bin_tree_t *prev = NULL;
	  while (node->right == prev || node->right == NULL)
	    {
	      prev = node;
	      node = node->parent;
	      dup_node = dup_node->parent;
	      if (!node)
		return dup_root;
	    }
	  node = node->right;
	  p_new = &dup_node->right;
	}
    }
}

Regex::Regex()
{
    compiled = false;
}

Regex::~Regex()
{
    if (compiled)
    {
        regfree(&regex);
        compiled = false;
    }
}

bool Regex::compile(string pattern, bool case_insensitive)
{
    if (compiled)
    {
        regfree(&regex);
        compiled = false;
    }

    this->pattern = pattern;

    int ret;
    if (case_insensitive)
        ret = regcomp(&regex, pattern.c_str(), REG_ICASE | REG_EXTENDED);
    else
        ret = regcomp(&regex, pattern.c_str(), REG_EXTENDED);

    if (ret == 0)
        compiled = true;

    return (ret == 0);
}

bool Regex::isCompiled()
{
    return compiled;
}

std::string Regex::getPattern()
{
    return pattern;
}

bool Regex::matches(std::string str)
{
    if (!compiled)
        return false;

    int ret = regexec(&regex, str.c_str(), 0, NULL, 0);

    if (ret == 0)
        return true;

    return false;
}

Match Regex::match(std::string str)
{    
    if (!compiled)
        return Match("");

    size_t ngroups = regex.re_nsub + 1;
    regmatch_t * pgroups = (regmatch_t *) malloc(ngroups * sizeof(regmatch_t));
    int ret = regexec(&regex, str.c_str(), ngroups, pgroups, 0);

    if (ret == 0)
    {
        Match m(str);
        for (int i=0; i<(int)ngroups; i++)
        {
            m.addGroup(pgroups[i].rm_so, pgroups[i].rm_eo);
        }

        free(pgroups);
        return m;
    }

    free(pgroups);
    return Match("");
}



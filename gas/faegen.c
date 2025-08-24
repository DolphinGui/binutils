#include "as.h"
#include "faegen.h"
#include "frags.h"
#include "read.h"
#include <stdint.h>

typedef struct {
  symbolS *proc_start;
  symbolS *unwinder;
  symbolS *personality_data;
  expressionS *size;
  size_t stack;
  size_t registers;
  char done;
  char dynamic_stack;
} _unwind;

static _unwind unwind;

static void dot_fae_start(int);
static void dot_fae_unwinder(int);
static void dot_fae_handlerdata(int);
static void dot_fae_end(int);
static void dot_fae_stacksize(int);
static void dot_fae_save_sp(int);
static void dot_fae_fsize(int);

const pseudo_typeS fae_pseudo_table[] = {
    {"fae_start", dot_fae_start, 0},
    {"fae_end", dot_fae_end, 0},
    {"fae_unwinder", dot_fae_unwinder, 0},
    {"fae_handlerdata", dot_fae_handlerdata, 0},
    {"fae_stacksize", dot_fae_stacksize, 0},
    {"fae_save_sp", dot_fae_save_sp, 0},
    {"fae_fsize", dot_fae_fsize, 0},
    {NULL, 0, 0}};

void dot_fae_start(int s ATTRIBUTE_UNUSED) {
  _unwind initial = {0};
  unwind = initial;
  unwind.proc_start = expr_build_dot();
  demand_empty_rest_of_line();
}

static void check_proc(void) {
  if (!unwind.proc_start) {
    as_bad(_("Missing .fae_start"));
  }

  if (unwind.done) {
    as_bad(_("Directive is outside of function"));
  }
}

static int immediate_for_directive(size_t *val);

static void expect_seperator(void) {
  SKIP_WHITESPACE();
  if (*input_line_pointer == ',')
    input_line_pointer++;
  else
    as_bad(_("missing separator"));
}

// TODO: make unwinder accept offset so registers_allocated can be removed
void dot_fae_unwinder(int s ATTRIBUTE_UNUSED) {
  check_proc();
  if (unwind.unwinder)
    as_bad(_("Duplicate .fae_unwinder directive"));
  char *symbol;
  char c = get_symbol_name(&symbol);
  unwind.unwinder = symbol_find_or_make(symbol);
  restore_line_pointer(c);
  expect_seperator();
  immediate_for_directive(&unwind.registers);
}

void dot_fae_handlerdata(int s ATTRIBUTE_UNUSED) {
  check_proc();
  char *symbol;
  get_symbol_name(&symbol);
  unwind.personality_data = symbol_find_or_make(symbol);
  demand_empty_rest_of_line();
}

// stolen from tc-arm, might be better to move somewhere else
// TODO: Fix to allow for different sizes by just returning expressionS*
static int immediate_for_directive(size_t *val) {
  expressionS exp;
  exp.X_op = O_illegal;

  expression_and_evaluate(&exp);

  if (exp.X_op != O_constant) {
    as_bad(_("expected a constant, got %d"), exp.X_op);
    ignore_rest_of_line();
    return -1;
  }
  if (exp.X_add_number < 0)
    as_bad(_("Expression is out of bounds"));
  *val = exp.X_add_number;
  return 0;
}

void dot_fae_stacksize(int s ATTRIBUTE_UNUSED) {
  check_proc();
  if (unwind.dynamic_stack)
    as_bad(_("Cannot set stack size for function with dynamic stack"));
  immediate_for_directive(&unwind.stack);
}

void dot_fae_fsize(int s ATTRIBUTE_UNUSED) {
  check_proc();
  if (unwind.dynamic_stack)
    as_bad(_("Cannot set stack size for function with dynamic stack"));
  unwind.size = XNEW(struct expressionS);
  expression(unwind.size);
}

void dot_fae_save_sp(int s ATTRIBUTE_UNUSED) {
  check_proc();
  if (unwind.stack != 0)
    as_bad(
        _("Cannot set stack pointer register for function with fixed stack"));
  immediate_for_directive(&unwind.stack);
  unwind.stack = 6 | ((size_t)1 << 63); // todo make this architecture-generic
}

static int start_section(const segT text_seg, const char *prefix,
                         const char *once) {
  const char *text_name;
  struct elf_section_match match;
  char *sec_name;
  int flags;
  int linkonce = 0;
  int is_sorted = 1;
  text_name = segment_name(text_seg);
  if (strcmp(text_name, ".text") == 0) {
    text_name = "";
    is_sorted = 0;
  }

  if (startswith(text_name, ".gnu.linkonce.t.")) {
    prefix = once;
    text_name += strlen(".gnu.linkonce.t.");
  }

  sec_name = concat(prefix, text_name, (char *)NULL);

  flags = SHF_ALLOC;
  memset(&match, 0, sizeof(match));

  /*
   * This is kinda bad, and realistically this should either be rewritten to be
   * format agnostic, or be put into config.
   */
  obj_elf_change_section(sec_name, SHT_PROGBITS, flags, 0, &match, linkonce);
  return is_sorted;
}

static int reloc_type(int ptr_size) {
#ifdef FAE_PTR_RELOC_TYPE
  return FAE_PTR_RELOC_TYPE;
#endif
  switch (ptr_size) {
  case 64:
    return BFD_RELOC_64;
  case 32:
    return BFD_RELOC_32;
  case 24:
    return BFD_RELOC_24;
  case 16:
    return BFD_RELOC_16;
  case 8:
    return BFD_RELOC_8;
  default:
    as_fatal(_("Relocation size %d is invalid"), ptr_size);
  }
}

static void emit_table(const segT text, int ptr_size, symbolS *end,
                       symbolS *data);
static symbolS *emit_data(const segT text, int ptr_size);

static void emit_size(const segT text, int ptr_size);

void dot_fae_end(int s ATTRIBUTE_UNUSED) {
  int ptr_size = stdoutput->arch_info->bits_per_address /
                 stdoutput->arch_info->bits_per_byte;

  if (!unwind.proc_start) {
    as_bad(_("fae_end directive without fae_start directive"));
  }
  if (unwind.done) {
    as_bad(_("Duplicate fae_end directive"));
  }
  if (!unwind.unwinder) {
    as_bad(_("No unwind routine specified!"));
  }

  symbolS *proc_end = expr_build_dot();
  demand_empty_rest_of_line();

  segT text = now_seg;
  subsegT subseg = now_subseg;

  emit_size(text, ptr_size);

  symbolS *data = emit_data(text, ptr_size);
  emit_table(text, ptr_size, proc_end, data);
  symbolS *unwind_begin = expr_build_dot();

  // Restore the original section.
  subseg_set(text, subseg);

  // indicate to linker script that function depends on section
  fix_new(frag_now, 0, 0, unwind_begin, 0, 0, BFD_RELOC_NONE);

  unwind.done = 1;
}

void emit_table(const segT text, int ptr_size, symbolS *end, symbolS *data) {
  int is_sorted = start_section(text, FAE_TBL_SECTION, FAE_TBL_SECTION_ONCE);
  long where = frag_now_fix();
  long size = is_sorted ? ptr_size : 3 * ptr_size;
  char* ptr = frag_more(size);
  memset(ptr, 0, ptr_size * size);
  const int type = reloc_type(ptr_size);

  fix_new(frag_now /* frag */, where /* offset */, ptr_size /* size */,
          unwind.proc_start /*symbol*/, 0 /*offset*/, 0, type);
  if (!is_sorted) {
    fix_new(frag_now, ptr_size + where, ptr_size, end, 0, 0, type);
    fix_new(frag_now, ptr_size * 2 + where, ptr_size, data, 0, 0, type);
  } else {
    // indicate to gc that this points to the data, even if it's not obvious
    fix_new(frag_now, where, 0, data, 0, 0, BFD_RELOC_NONE);
  }
}

symbolS *emit_data(const segT t, int ptr_size) {
  start_section(t, FAE_DATA_SECTION, FAE_DATA_SECTION_ONCE);
  symbolS *table = expr_build_dot();
  long where = frag_now_fix();
  char *ptr = frag_more(4 * ptr_size);
  memset(ptr, 0, ptr_size * 4);
  const int type = reloc_type(ptr_size);

  memcpy(ptr, &unwind.stack, ptr_size);
  memcpy(ptr + ptr_size, &unwind.registers, ptr_size);
  fix_new(frag_now, ptr_size * 2 + where, ptr_size, unwind.unwinder, 0, 0,
          type);

  if (unwind.personality_data) {
    fix_new(frag_now, ptr_size * 3 + where, ptr_size, unwind.personality_data,
            0, 0, type);
  }
  return table;
}

void emit_size(const segT t, int ptr_size) {
  if (!unwind.size)
    return;
  start_section(t, FAE_SIZE_SECTION, FAE_SIZE_SECTION_ONCE);
  frag_more(ptr_size);
  const int type = reloc_type(ptr_size);
  fix_new_exp(frag_now, 0, ptr_size, unwind.size, 0, type);
}

#include "as.h"
#include "faegen.h"
#include <stdint.h>

typedef struct {
  symbolS *proc_start;
  symbolS *unwinder;
  symbolS *personality_routine;
  symbolS *personality_data;
  int registers_allocated;
  int stack_usage;
  int fp;
  int done;
} _unwind;

static _unwind unwind;

static void dot_fae_start(int);
static void dot_fae_unwinder(int);
static void dot_fae_personality(int);
static void dot_fae_handlerdata(int);
static void dot_fae_push(int);
static void dot_fae_allocate(int);
static void dot_fae_setfp(int);
static void dot_fae_end(int);

const pseudo_typeS fae_pseudo_table[] = {
    {"fae_start", dot_fae_start, 0},
    {"fae_end", dot_fae_end, 0},
    {"fae_unwinder", dot_fae_unwinder, 0},
    {"fae_personality", dot_fae_personality, 0},
    {"fae_handlerdata", dot_fae_handlerdata, 0},
    {"fae_push", dot_fae_push, 0},
    {"fae_allocate", dot_fae_allocate, 0},
    {"fae_setfp", dot_fae_setfp, 0},
    {NULL, 0, 0}};

void dot_fae_start(int s ATTRIBUTE_UNUSED) {
  _unwind initial = {0};
  unwind = initial;
  unwind.proc_start = expr_build_dot();
  demand_empty_rest_of_line();
}

static void emit_location(symbolS **out, const char *name) {
  char *symbol;
  if (!unwind.proc_start) {
    as_bad(_("Missing .fae_start"));
  }

  if (*out) {
    as_bad(_("Duplicate %s directive"), name);
  }

  if (unwind.done) {
    as_bad(_("Directive is outside of function"));
  }

  get_symbol_name(&symbol);
  *out = symbol_find_or_make(symbol);
  demand_empty_rest_of_line();
}

void dot_fae_unwinder(int s ATTRIBUTE_UNUSED) {
  emit_location(&unwind.unwinder, "fae_unwinder");
}

void dot_fae_handlerdata(int s ATTRIBUTE_UNUSED) {
  emit_location(&unwind.personality_data, "fae_handlerdata");
}

void dot_fae_personality(int s ATTRIBUTE_UNUSED) {
  emit_location(&unwind.personality_routine, "fae_personality");
}

void dot_fae_push(int s ATTRIBUTE_UNUSED) {
  if (!unwind.proc_start) {
    as_bad(_("Missing .fae_start"));
  }

  if (unwind.done) {
    as_bad(_("fae_push directive is outside of function"));
  }

  unwind.registers_allocated += 1;
  demand_empty_rest_of_line();
}

// stolen from tc-arm, might be better to move somewhere else
static int immediate_for_directive(int *val) {
  expressionS exp;
  exp.X_op = O_illegal;

  expression(&exp);

  if (exp.X_op != O_constant) {
    as_bad(_("expected a constant"));
    ignore_rest_of_line();
    return -1;
  }
  *val = exp.X_add_number;
  return 0;
}

void dot_fae_allocate(int s ATTRIBUTE_UNUSED) {
  if (!unwind.proc_start) {
    as_bad(_("Missing .fae_start"));
  }

  if (unwind.done) {
    as_bad(_("fae_allocate directive is outside of function"));
  }

  if (unwind.stack_usage != 0) {
    as_bad(_("Duplicate fae_allocate directive"));
  }

  immediate_for_directive(&unwind.stack_usage);
}

void dot_fae_setfp(int s ATTRIBUTE_UNUSED) {
  if (!unwind.proc_start) {
    as_bad(_("Missing .fae_start"));
  }

  if (unwind.done) {
    as_bad(_("fae_allocate directive is outside of function"));
  }

  if (unwind.stack_usage != 0) {
    as_bad(_("Duplicate fae_setfp directive"));
  }

  immediate_for_directive(&unwind.fp);
}

static void start_unwind_section(const segT text_seg) {
  const char *text_name;
  const char *prefix;
  struct elf_section_match match;
  char *sec_name;
  int flags;
  int linkonce = 0;
  text_name = segment_name(text_seg);
  prefix = FAE_TBL_SECTION;
  if (strcmp(text_name, ".text") == 0)
    text_name = "";

  if (startswith(text_name, ".gnu.linkonce.t.")) {
    prefix = FAE_TBL_SECTION_ONCE;
    text_name += strlen(".gnu.linkonce.t.");
  }

  sec_name = concat(prefix, text_name, (char *)NULL);

  flags = SHF_ALLOC;
  memset(&match, 0, sizeof(match));

  obj_elf_change_section(sec_name, SHT_PROGBITS, flags, 0, &match, linkonce);
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

static void write_constant(char *ptr, int size, int n) {
  switch (size) {
  case 64:
    *((uint64_t *)(ptr)) = n;
    break;
  case 32:
    *((uint32_t *)(ptr)) = n;
    break;
  case 16:
    *((uint16_t *)(ptr)) = n;
    break;
  case 8:
    *((uint8_t *)(ptr)) = n;
    break;
  default:
    as_fatal(_("Could not write a valid size in fae table"));
  }
}

void dot_fae_end(int s ATTRIBUTE_UNUSED) {

  long where;
  char *ptr;
  int register_size =
      stdoutput->arch_info->bits_per_word / stdoutput->arch_info->bits_per_byte;

  int ptr_size = stdoutput->arch_info->bits_per_address /
                 stdoutput->arch_info->bits_per_byte;

  if (!unwind.proc_start) {
    as_bad(_("fae_end directive without fae_start directive"));
  }
  if (unwind.done) {
    as_bad(_("Duplicate fae_end directive"));
  }

  unwind.stack_usage += register_size * unwind.registers_allocated;

  symbolS *proc_end = expr_build_dot();
  demand_empty_rest_of_line();

  segT text = now_seg;
  subsegT subtext = now_subseg;

  start_unwind_section(text);
  symbolS *unwind_begin = expr_build_dot();

  int len = register_size * 2 + ptr_size * 5;
  ptr = frag_more(len);
  where = frag_now_fix() - len;

  int type = reloc_type(ptr_size);

  memset(ptr, 0, len);
  fix_new(frag_now, where, ptr_size, unwind.proc_start, 0, 0, type);
  where += ptr_size;
  fix_new(frag_now, where, ptr_size, proc_end, 0, 0, type);
  where += ptr_size;
  fix_new(frag_now, where, ptr_size, unwind.unwinder, 0, 0, type);
  where += ptr_size;
  write_constant(ptr + where, register_size, unwind.registers_allocated);
  where += register_size;
  write_constant(ptr + where, register_size, unwind.fp);
  where += register_size;

  if (unwind.personality_routine) {
    fix_new(frag_now, where, ptr_size, unwind.personality_routine, 0, 0, type);
    where += ptr_size;
    if (!unwind.personality_data) {
      as_bad(_("No fae_personality_data to match with personality routine"));
    }
    fix_new(frag_now, where, ptr_size, unwind.personality_data, 0, 0, type);
    where += ptr_size;
  }
  /* Restore the original section.  */
  subseg_set(text_section, subtext);

  // indicate to linker script that function depends on section
  fix_new(frag_now, 0, 0, unwind_begin, 0, 0, BFD_RELOC_NONE);

  unwind.done = 1;
}

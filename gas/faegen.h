/* faegen.h - Support for generating Dwarf2 CFI information.
   Copyright (C) 2003-2024 Free Software Foundation, Inc.
   Contributed by Michal Ludvig <mludvig@suse.cz>

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef FAEGEN_H
#define FAEGEN_H

#include "as.h"

extern const pseudo_typeS fae_pseudo_table[];

extern void fae_finish (void);

#define FAE_TBL_SECTION ".fae.table" 

#define FAE_TBL_SECTION_ONCE ".fae.table" 

// define FAE_PTR_RELOC_TYPE to specify a relocation type for function pointers

#endif

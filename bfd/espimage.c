/* BFD back-end for Espressif ESP image objects.
   Copyright 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003,
   2004, 2005, 2006, 2007, 2009, 2011 Free Software Foundation, Inc.
   Written by Ian Lance Taylor, Cygnus Support, <ian@cygnus.com>

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/* This is a BFD backend which may be used to read and write firmware
   images for Espressif's ESP SoC modules. This format is used for
   firmware updates for both OTA and UART.

   The overall file format is

     File header (see ESPIMAGE_FILEHEADER_SIZE)
     (
       Section header (see ESPIMAGE_SECHEADER_SIZE)
       Raw section data
     )*
     Padding (see ESPIMAGE_TRAILER_ALIGN)
     Checksum covering all raw section data  */

#include "sysdep.h"
#include "bfd.h"
#include "safe-ctype.h"
#include "libbfd.h"


/* The file header magic.  */
#define ESPIMAGE_MAGIC 0xE9

/* Constant value for checksum calculations.  */
#define ESPIMAGE_CHECKSUM_INIT 0xEF

/* Alignment of the trailing checksum, in bytes.  */
#define ESPIMAGE_TRAILER_ALIGN 16

/* Location of dram0, used to guess section name .data on reading.  */
#define ESPIMAGE_DRAM0_VADDR 0x3FFE8000

/* Location of iram0, used to guess section name .text on reading.  */
#define ESPIMAGE_IRAM0_VADDR 0x40100000

/* Size of the file header.  The header is

      Offset | Size |  Name  | Description
     --------+------+--------+-------------
           0 |    1 | magic  | The signature value ESPIMAGE_MAGIC
           1 |    1 | numsec | Number of section in the file
           2 |    2 | pad    | Zero-padding
           4 |    4 | start  | Start address when executing  */
#define ESPIMAGE_FILEHEADER_SIZE 8

/* Size of each section header.  The header is

      Offset | Size |  Name  | Description
     --------+------+--------+-------------
           0 |    4 | vma    | The virtual address to load at
           4 |    4 | size   | The size of the section data, in bytes  */
#define ESPIMAGE_SECHEADER_SIZE 8

/* Check if the given section flags indicate a section we should write
   to an image file.  */
#define ESPIMAGE_WRITABLE_SECTION(flags) \
  (((flags) & (SEC_HAS_CONTENTS | SEC_LOAD | SEC_ALLOC | SEC_NEVER_LOAD)) \
  == (SEC_HAS_CONTENTS | SEC_LOAD | SEC_ALLOC))


/* Section-specific backend data.  */
typedef struct
{
  /* Checksum accumulator used when writing the image.  */
  unsigned int checksum;
} section_data_t;


/* Entry: Create an espimage object.  Invoked via bfd_set_format.  */
static bfd_boolean
espimage_mkobject (bfd *abfd ATTRIBUTE_UNUSED)
{
  return TRUE;
}

/* Read an input file slice and accumulate a checksum.  */
static bfd_boolean
scan_section_checksum (bfd *abfd, bfd_size_type size,
				unsigned int *checksum)
{
  bfd_byte buf[4096];

  while (size)
    {
      bfd_size_type len = (size < sizeof (buf) ? size : sizeof (buf));
      unsigned int i;

      if (bfd_bread (buf, len, abfd) != len)
	return FALSE;

      for (i = 0; i < len; ++i)
	*checksum ^= buf[i];

      size -= len;
    }

  return TRUE;
}

/* Flags for used_names in make_section_name.  */
#define UN_TEXT   0x01
#define UN_DATA   0x02

/* Compute a good section name.  This uses a heuristic to find .text and
   .data, but falls back to ".secX".  Returns a newly allocated string.  */
static char *
make_section_name (unsigned int index, bfd_vma vma, flagword *used_names)
{
  const char *prefix;
  unsigned int suffix = index + 1;
  char buf[16];

  if (vma >= ESPIMAGE_IRAM0_VADDR)
    {
      prefix = ".text";
      if (!(*used_names & UN_TEXT))
	{
	  /* This was the first section looking like a .text, so no suffix.  */
	  *used_names |= UN_TEXT;
	  suffix = 0;
	}
    }
  else if (vma >= ESPIMAGE_DRAM0_VADDR)
    {
      prefix = ".data";
      if (!(*used_names & UN_DATA))
	{
	  /* This was the first section looking like a .data, so no suffix.  */
	  *used_names |= UN_DATA;
	  suffix = 0;
	}
    }
  else
    {
      /* Fallback to .sec.  */
      prefix = ".sec";
    }

  if (suffix)
    sprintf (buf, "%s%d", prefix, suffix);
  else
    strcpy (buf, prefix);

  return strdup (buf);
}

/* Create a new private section data object.  Returns a newly allocated
   object.  */
static section_data_t *
make_section_data (bfd *abfd)
{
  section_data_t *ret = bfd_alloc (abfd, sizeof (section_data_t));

  if (ret == NULL)
    return NULL;

  ret->checksum = 0;

  return ret;
}

/* Create a new section object, including our private data.  */
static asection *
make_section (bfd *abfd, char * name, flagword flags)
{
  asection *ret = bfd_make_section_with_flags (abfd, name, flags);

  if (ret == NULL)
    return NULL;

  ret->used_by_bfd = make_section_data (abfd);
  if (ret->used_by_bfd == NULL)
    {
      free (ret);
      return NULL;
    }

  return ret;
}

/* Scan an input file and create section objects for each found.  */
static bfd_boolean
scan_sections (bfd *abfd, unsigned int num_sections)
{
  bfd_byte secheader[ESPIMAGE_SECHEADER_SIZE];
  unsigned int i;
  file_ptr fpos = bfd_tell (abfd);
  unsigned int checksum = ESPIMAGE_CHECKSUM_INIT;
  flagword used_names = 0;

  for (i = 0; i < num_sections; ++i)
    {
      char *secname = NULL;
      asection *sec;
      bfd_vma vaddr;

      if (bfd_bread (secheader, (bfd_size_type) sizeof (secheader), abfd)
	  != (bfd_size_type) sizeof (secheader))
	return FALSE;

      fpos += 8;

      vaddr = bfd_getl32 (secheader);
      secname = make_section_name (i, vaddr, &used_names);
      sec = make_section (abfd, secname,
			  SEC_ALLOC | SEC_LOAD | SEC_ROM | SEC_HAS_CONTENTS);
      if (sec == NULL)
	{
	  free (secname);
	  return FALSE;
	}

      sec->vma = vaddr;
      sec->lma = fpos;
      sec->size = bfd_getl32 (&secheader[4]);
      sec->filepos = fpos;

      if (!scan_section_checksum (abfd, sec->size, &checksum))
	return FALSE;

      fpos += sec->size;
    }

  /* Reuse the secheader buffer to read the checksum.  */
  fpos += ESPIMAGE_TRAILER_ALIGN - 1 - fpos % ESPIMAGE_TRAILER_ALIGN;
  if (bfd_seek (abfd, fpos, SEEK_SET) != 0
      || bfd_bread (secheader, 1, abfd) != 1)
    return FALSE;

  if (secheader[0] != checksum)
    {
      (*_bfd_error_handler)(_("%B: Bad checksum (calc 0x%02X, read 0x02X)\n"),
			    abfd, checksum, secheader[0]);
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  return TRUE;
}

/* Entry: Check if the file is in a supported format, and load headers.  */
static const bfd_target *
espimage_object_p (bfd *abfd)
{
  bfd_byte fileheader[ESPIMAGE_FILEHEADER_SIZE];
  unsigned int num_sections;

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0
      || bfd_bread (fileheader, (bfd_size_type) sizeof (fileheader), abfd)
      != (bfd_size_type) sizeof (fileheader))
    return NULL;

  /* Ignore files with no sections as no official tool produces such files.  */
  if (fileheader[0] != ESPIMAGE_MAGIC || fileheader[1] == 0
      || fileheader[2] != 0 || fileheader[3] != 0)
    {
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }
  
  num_sections = fileheader[1];
  abfd->start_address = bfd_getl32 (&fileheader[4]);

  if (!scan_sections (abfd, num_sections))
    return NULL;

  /* Guess that we are using the Xtensa architecture.  */
  bfd_default_set_arch_mach (abfd, bfd_arch_xtensa, 0L);

  return abfd->xvec;
}

#define espimage_close_and_cleanup     _bfd_generic_close_and_cleanup
#define espimage_bfd_free_cached_info  _bfd_generic_bfd_free_cached_info
#define espimage_new_section_hook      _bfd_generic_new_section_hook
#define espimage_get_section_contents  _bfd_generic_get_section_contents

/* Entry: Return the amount of memory needed to read the symbol table,
   including the trailing NULL pointer.  */
static long
espimage_get_symtab_upper_bound (bfd *abfd ATTRIBUTE_UNUSED)
{
  return sizeof (asymbol *);
}

/* Entry: Return the (empty) symbol table.  */
static long
espimage_canonicalize_symtab (bfd *abfd ATTRIBUTE_UNUSED,
			      asymbol **alocation)
{
  *alocation = NULL;
  return 0;
}

#define espimage_make_empty_symbol  _bfd_generic_make_empty_symbol
#define espimage_print_symbol       _bfd_nosymbols_print_symbol

/* Entry: Get information about a symbol.  */
static void
espimage_get_symbol_info (bfd *ignore_abfd ATTRIBUTE_UNUSED,
			  asymbol *symbol,
			  symbol_info *ret)
{
  bfd_symbol_info (symbol, ret);
}

#define espimage_bfd_is_local_label_name      bfd_generic_is_local_label_name
#define espimage_get_lineno                  _bfd_nosymbols_get_lineno
#define espimage_find_nearest_line           _bfd_nosymbols_find_nearest_line
#define espimage_find_inliner_info           _bfd_nosymbols_find_inliner_info
#define espimage_bfd_make_debug_symbol       _bfd_nosymbols_bfd_make_debug_symbol
#define espimage_read_minisymbols            _bfd_generic_read_minisymbols
#define espimage_minisymbol_to_symbol        _bfd_generic_minisymbol_to_symbol
#define espimage_bfd_is_target_special_symbol ((bfd_boolean (*) (bfd *, asymbol *)) bfd_false)
#define espimage_set_arch_mach                _bfd_generic_set_arch_mach

/* Entry: Write section contents to an image file.  */
static bfd_boolean
espimage_set_section_contents (bfd *abfd,
			       asection *sec,
			       const void *data,
			       file_ptr offset,
			       bfd_size_type size)
{
  section_data_t *secdata = (section_data_t *)sec->used_by_bfd;
  bfd_size_type i;

  if (!ESPIMAGE_WRITABLE_SECTION (sec->flags))
    return TRUE;

  if (!abfd->output_has_begun)
    {
      file_ptr fpos = ESPIMAGE_FILEHEADER_SIZE;
      asection * s;

      /* Compute the file position for each section.  */
      for (s = abfd->sections; s != NULL; s = s->next)
	{
	  if (ESPIMAGE_WRITABLE_SECTION (s->flags))
	    {
	      fpos += ESPIMAGE_SECHEADER_SIZE;
	      s->filepos = fpos;
	      fpos += s->size;
	    }
	}

      abfd->output_has_begun = TRUE;
    }

  if (secdata == NULL)
    {
      sec->used_by_bfd = secdata = make_section_data (abfd);
      if (secdata == NULL)
	return FALSE;
    }

  /* Accumulate some checksum.  Note this assumes (1) checksumming is a
     commutative operation, and (2) set_section_contents is called exactly once
     for each byte of the section data.  */
  for (i = 0; i < size; ++i)
    secdata->checksum ^= ((const bfd_byte *)data)[i];

  /* Perform the actual write.  */
  return _bfd_generic_set_section_contents (abfd, sec, data, offset, size);
}

/* Entry: Return the size of our file header.  */
static int
espimage_sizeof_headers (bfd *abfd ATTRIBUTE_UNUSED,
		       struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return ESPIMAGE_FILEHEADER_SIZE;
}

#define espimage_bfd_get_relocated_section_contents  bfd_generic_get_relocated_section_contents
#define espimage_bfd_relax_section                   bfd_generic_relax_section
#define espimage_bfd_gc_sections                     bfd_generic_gc_sections
#define espimage_bfd_lookup_section_flags            bfd_generic_lookup_section_flags
#define espimage_bfd_merge_sections                  bfd_generic_merge_sections
#define espimage_bfd_is_group_section                bfd_generic_is_group_section
#define espimage_bfd_discard_group                   bfd_generic_discard_group
#define espimage_section_already_linked             _bfd_generic_section_already_linked
#define espimage_bfd_define_common_symbol            bfd_generic_define_common_symbol
#define espimage_bfd_link_hash_table_create         _bfd_generic_link_hash_table_create
#define espimage_bfd_link_hash_table_free           _bfd_generic_link_hash_table_free
#define espimage_bfd_link_just_syms                 _bfd_generic_link_just_syms
#define espimage_bfd_copy_link_hash_symbol_type     _bfd_generic_copy_link_hash_symbol_type
#define espimage_bfd_link_add_symbols               _bfd_generic_link_add_symbols
#define espimage_bfd_final_link                     _bfd_generic_final_link
#define espimage_bfd_link_split_section             _bfd_generic_link_split_section
#define espimage_get_section_contents_in_window     _bfd_generic_get_section_contents_in_window

/* Entry: Finalize writing an object by writing its headers.  This is called
   after set_section_contents has been called for all sections.  */
static bfd_boolean
espimage_write_object_contents (bfd *abfd)
{
  bfd_byte fileheader[ESPIMAGE_FILEHEADER_SIZE];
  asection *sec;
  unsigned int checksum = ESPIMAGE_CHECKSUM_INIT;
  file_ptr end = ESPIMAGE_FILEHEADER_SIZE;

  /* Write the file header.  */
  fileheader[0] = ESPIMAGE_MAGIC;
  fileheader[1] = 0;

  for (sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      if (ESPIMAGE_WRITABLE_SECTION(sec->flags))
	++fileheader[1];
    }

  fileheader[2] = 0;
  fileheader[3] = 0;
  bfd_putl32 (bfd_get_start_address (abfd), &fileheader[4]);

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0
      || bfd_bwrite (fileheader, sizeof (fileheader), abfd)
      != sizeof (fileheader))
    return FALSE;

  /* Write the section headers.  */
  for (sec = abfd->sections; sec != NULL; sec = sec->next)
    {
      bfd_byte secheader[ESPIMAGE_SECHEADER_SIZE];

      if (!ESPIMAGE_WRITABLE_SECTION(sec->flags))
	continue;

      bfd_putl32 (sec->vma, secheader);
      bfd_putl32 (sec->size, &secheader[4]);
      
      if (sec->filepos < ESPIMAGE_SECHEADER_SIZE)
	{
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}

      if (bfd_seek (abfd, sec->filepos - ESPIMAGE_SECHEADER_SIZE, SEEK_SET) != 0
	  || bfd_bwrite (secheader, sizeof (secheader), abfd)
	  != sizeof (secheader))
	return FALSE;

      /* Accumulate checksum. This assumes checksumming is associative.  */
      if (sec->used_by_bfd != NULL)
	checksum ^= ((section_data_t *)sec->used_by_bfd)->checksum;

      if (sec->filepos + (file_ptr) sec->size > end)
	end = sec->filepos + sec->size;
    }

  /* Write the checksum, reusing the fileheader buffer.  */
  fileheader[0] = (bfd_byte) checksum;

  end += ESPIMAGE_TRAILER_ALIGN - 1 - end % ESPIMAGE_TRAILER_ALIGN;
  if (bfd_seek (abfd, end, SEEK_SET) != 0
      || bfd_bwrite (fileheader, 1, abfd) != 1)
    return FALSE;

  return TRUE;
}

/* The target structure used for registration in targets.c.  */
const bfd_target espimage_vec =
{
  "espimage",			/* name */
  bfd_target_unknown_flavour,	/* flavour */
  BFD_ENDIAN_LITTLE,		/* byteorder */
  BFD_ENDIAN_LITTLE,		/* header_byteorder */
  EXEC_P,			/* object_flags */
  (SEC_ALLOC | SEC_LOAD | SEC_READONLY | SEC_CODE | SEC_DATA
   | SEC_ROM | SEC_HAS_CONTENTS), /* section_flags */
  0,				/* symbol_leading_char */
  ' ',				/* ar_pad_char */
  16,				/* ar_max_namelen */
  255,				/* match priority.  */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16,	/* data */
  bfd_getl64, bfd_getl_signed_64, bfd_putl64,
  bfd_getl32, bfd_getl_signed_32, bfd_putl32,
  bfd_getl16, bfd_getl_signed_16, bfd_putl16,	/* hdrs */
  {				/* bfd_check_format */
    _bfd_dummy_target,
    espimage_object_p,
    _bfd_dummy_target,
    _bfd_dummy_target,
  },
  {				/* bfd_set_format */
    bfd_false,
    espimage_mkobject,
    bfd_false,
    bfd_false,
  },
  {				/* bfd_write_contents */
    bfd_false,
    espimage_write_object_contents,
    bfd_false,
    bfd_false,
  },

  BFD_JUMP_TABLE_GENERIC (espimage),
  BFD_JUMP_TABLE_COPY (_bfd_generic),
  BFD_JUMP_TABLE_CORE (_bfd_nocore),
  BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
  BFD_JUMP_TABLE_SYMBOLS (espimage),
  BFD_JUMP_TABLE_RELOCS (_bfd_norelocs),
  BFD_JUMP_TABLE_WRITE (espimage),
  BFD_JUMP_TABLE_LINK (espimage),
  BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

  NULL,

  NULL
};

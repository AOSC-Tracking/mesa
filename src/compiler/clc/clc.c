/*
 * Copyright © Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "nir/nir.h"
#include "nir/nir_serialize.h"
#include "glsl_types.h"
#include "clc.h"
#include "clc_helpers.h"
#include "nir_clc_helpers.h"
#include "spirv/nir_spirv.h"
#include "util/u_debug.h"

#include <stdlib.h>

static const struct debug_named_value clc_debug_options[] = {
   { "dump_spirv",  CLC_DEBUG_DUMP_SPIRV, "Dump spirv blobs" },
   { "dump_llvm",  CLC_DEBUG_DUMP_LLVM, "Dump LLVM blobs" },
   { "verbose",  CLC_DEBUG_VERBOSE, NULL },
   DEBUG_NAMED_VALUE_END
};

DEBUG_GET_ONCE_FLAGS_OPTION(debug_clc, "CLC_DEBUG", clc_debug_options, 0)

uint64_t clc_debug_flags(void)
{
   return debug_get_option_debug_clc();
}

static void
clc_print_kernels_info(const struct clc_parsed_spirv *obj)
{
   fprintf(stdout, "Kernels:\n");
   for (unsigned i = 0; i < obj->num_kernels; i++) {
      const struct clc_kernel_arg *args = obj->kernels[i].args;
      bool first = true;

      fprintf(stdout, "\tvoid %s(", obj->kernels[i].name);
      for (unsigned j = 0; j < obj->kernels[i].num_args; j++) {
         if (!first)
            fprintf(stdout, ", ");
         else
            first = false;

         switch (args[j].address_qualifier) {
         case CLC_KERNEL_ARG_ADDRESS_GLOBAL:
            fprintf(stdout, "__global ");
            break;
         case CLC_KERNEL_ARG_ADDRESS_LOCAL:
            fprintf(stdout, "__local ");
            break;
         case CLC_KERNEL_ARG_ADDRESS_CONSTANT:
            fprintf(stdout, "__constant ");
            break;
         default:
            break;
         }

         if (args[j].type_qualifier & CLC_KERNEL_ARG_TYPE_VOLATILE)
            fprintf(stdout, "volatile ");
         if (args[j].type_qualifier & CLC_KERNEL_ARG_TYPE_CONST)
            fprintf(stdout, "const ");
         if (args[j].type_qualifier & CLC_KERNEL_ARG_TYPE_RESTRICT)
            fprintf(stdout, "restrict ");

         fprintf(stdout, "%s %s", args[j].type_name, args[j].name);
      }
      fprintf(stdout, ");\n");
   }
}

bool
clc_compile_c_to_spir(const struct clc_compile_args *args,
                      const struct clc_logger *logger,
                      struct clc_binary *out_spir,
                      struct set *dependencies)
{
   return clc_c_to_spir(args, logger, out_spir, dependencies) >= 0;
}

void
clc_free_spir(struct clc_binary *spir)
{
   clc_free_spir_binary(spir);
}

bool
clc_compile_spir_to_spirv(const struct clc_binary *in_spir,
                          const struct clc_logger *logger,
                          struct clc_binary *out_spirv)
{
   if (clc_spir_to_spirv(in_spir, logger, out_spirv) < 0)
      return false;

   if (debug_get_option_debug_clc() & CLC_DEBUG_DUMP_SPIRV)
      clc_dump_spirv(out_spirv, stdout);

   return true;
}

void
clc_free_spirv(struct clc_binary *spirv)
{
   clc_free_spirv_binary(spirv);
}

bool
clc_compile_c_to_spirv(const struct clc_compile_args *args,
                       const struct clc_logger *logger,
                       struct clc_binary *out_spirv,
                       struct set *dependencies)
{
   if (clc_c_to_spirv(args, logger, out_spirv, dependencies) < 0)
      return false;

   if (debug_get_option_debug_clc() & CLC_DEBUG_DUMP_SPIRV)
      clc_dump_spirv(out_spirv, stdout);

   return true;
}

bool
clc_link_spirv(const struct clc_linker_args *args,
               const struct clc_logger *logger,
               struct clc_binary *out_spirv)
{
   if (clc_link_spirv_binaries(args, logger, out_spirv) < 0)
      return false;

   if (debug_get_option_debug_clc() & CLC_DEBUG_DUMP_SPIRV)
      clc_dump_spirv(out_spirv, stdout);

   return true;
}

bool
clc_parse_spirv(const struct clc_binary *in_spirv,
                const struct clc_logger *logger,
                struct clc_parsed_spirv *out_data)
{
   if (!clc_spirv_get_kernels_info(in_spirv,
      &out_data->kernels,
      &out_data->num_kernels,
      &out_data->spec_constants,
      &out_data->num_spec_constants,
      logger))
      return false;

   if (debug_get_option_debug_clc() & CLC_DEBUG_VERBOSE)
      clc_print_kernels_info(out_data);

   return true;
}

void clc_free_parsed_spirv(struct clc_parsed_spirv *data)
{
   clc_free_kernels_info(data->kernels, data->num_kernels);
}

bool
clc_specialize_spirv(const struct clc_binary *in_spirv,
                     const struct clc_parsed_spirv *parsed_data,
                     const struct clc_spirv_specialization_consts *consts,
                     struct clc_binary *out_spirv)
{
   if (!clc_spirv_specialize(in_spirv, parsed_data, consts, out_spirv))
      return false;

   if (debug_get_option_debug_clc() & CLC_DEBUG_DUMP_SPIRV)
      clc_dump_spirv(out_spirv, stdout);

   return true;
}

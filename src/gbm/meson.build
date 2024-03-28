# Copyright © 2017 Intel Corporation

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

inc_gbm = include_directories('.', 'main', 'backends/dri')

files_gbm = files(
  'main/gbm_backend_abi.h',
)
deps_gbm = []
args_gbm = []
incs_gbm = [
  include_directories('main'), inc_include, inc_src, inc_loader,
]

if with_dri2
  files_gbm += files('backends/dri/gbm_dri.c', 'backends/dri/gbm_driint.h')
  deps_gbm += dep_libdrm # TODO: pthread-stubs
endif
if with_platform_wayland
  deps_gbm += dep_wayland_server
  incs_gbm += inc_wayland_drm
endif

amber_gbm = shared_library(
  'amber_gbm',
  files_gbm,
  include_directories : incs_gbm,
  c_args : [args_gbm],
  link_args : [ld_args_gc_sections],
  link_with : libloader,
  dependencies : [deps_gbm, dep_dl, dep_thread, idep_mesautil, idep_xmlconfig],
  gnu_symbol_visibility : 'hidden',
  install : true,
  install_dir : gbm_backends_path,
  name_prefix : '',
  name_suffix : 'so',
)

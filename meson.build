project('libdiary', 'c',
  version : '0.0.1',
  license : 'GPL-3.0-or-later',
  default_options : [
    'warning_level=2',
    'optimization=3'
  ],
)

libdiary_name = 'diary'

add_global_arguments(['-D_GNU_SOURCE', '-DSQLITE_MAX_LENGTH=2147483647'], language : 'c')

sqlite3_dep = dependency('sqlite3', version : '>=3.45.0')
libsodium_dep = dependency('libsodium')
glib_dep = dependency('glib-2.0')
gio_dep = dependency('gio-2.0')
cjson_dep = dependency('libcjson')

top_includepath = include_directories('.')

subdir('libdiary')
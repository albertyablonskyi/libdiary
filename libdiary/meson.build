libdiary_sources = [
  'libdiary.c',
  'libdiary_log.c'
]


libdiary = library(libdiary_name,
  sources: [
    libdiary_sources,
  ],
  dependencies: [
    sqlite3_dep,
    libsodium_dep,
    gio_dep,
    glib_dep,
    cjson_dep
  ],
  install: true
)

libdiary_dep = declare_dependency(
  link_with: libdiary
)

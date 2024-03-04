 # libdiary - protected personal diary

libdiary is a C library designed for personal diary with additional features like:
- attaching files
- exporting files
- opening files without exporting to a disk (basically exporting file to a /tmp/ folder and opening with default app)
- encryption with XChaCha20-Poly1305

## Dependencies
- `meson`
- `ninja`
- `glib`
- `libsodium`

## Build & Run
``` sh
$ git clone https://github.com/albertyablonskyi/libdiary
$ meson setup build
$ ninja -C build install
$ python diary_cli.py
```

### Explaination

**diary_cli.py** is a Python CLI program to interact with libdiary. It uses **diary.py**, which is a wrapper for calling libdiary C functions using ctypes.
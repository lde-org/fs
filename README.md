# fs

A cross platform `fs` library for [lde](https://lde.sh).

It allows you to do things from recursively walk a directory, to set file permissions and create symlinks.

## Usage

```
lde add fs --git https://github.com/lde-org/fs
```

## Paths

Paths are UTF-8 strings on every platform. On Windows, fs talks to the wide (UTF-16) Win32 calls and
converts at the boundary, so a name outside the system code page (`Antônio`, `日本`, an emoji) is
listed, opened and created like any other.

Loading fs on Windows also sets the Universal CRT's `LC_CTYPE` locale to `.UTF8`, so `io.open`,
`os.remove`, `os.rename` and `fopen` in native modules take the same UTF-8 paths fs hands back. Number
and date formatting are untouched. A process on a C runtime older than the Universal CRT keeps its
code page, and non-ASCII paths cannot be opened through `io.open` there.

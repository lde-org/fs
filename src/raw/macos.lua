local ffi = require("ffi")

ffi.cdef([[typedef uint64_t ino_t;]])

ffi.cdef([[
	struct timespec {
		long tv_sec;
		long tv_nsec;
	};
]])

if jit.arch == "arm64" then
	ffi.cdef([[
		struct stat {
			int32_t         st_dev;
			uint16_t        st_mode;
			uint16_t        st_nlink;
			ino_t           st_ino;
			uint32_t        st_uid;
			uint32_t        st_gid;
			int32_t         st_rdev;
			struct timespec st_atimespec;
			struct timespec st_mtimespec;
			struct timespec st_ctimespec;
			struct timespec st_birthtimespec;
			int64_t         st_size;
			int64_t         st_blocks;
			int32_t         st_blksize;
			uint32_t        st_flags;
			uint32_t        st_gen;
			int32_t         st_lspare;
			int64_t         st_qspare[2];
		};

		struct dirent {
			ino_t d_ino;
			uint64_t d_seekoff;
			uint16_t d_reclen;
			uint16_t d_namlen;
			uint8_t  d_type;
			char     d_name[1024];
		};
	]])
else
	-- x86-64 macOS: plain `stat` uses old 32-bit inode layout; must use stat$INODE64
	ffi.cdef([[
		struct stat {
			int32_t         st_dev;
			uint16_t        st_mode;
			uint16_t        st_nlink;
			ino_t           st_ino;
			uint32_t        st_uid;
			uint32_t        st_gid;
			int32_t         st_rdev;
			int32_t         st_rdev_pad;
			struct timespec st_atimespec;
			struct timespec st_mtimespec;
			struct timespec st_ctimespec;
			struct timespec st_birthtimespec;
			int64_t         st_size;
			int64_t         st_blocks;
			int32_t         st_blksize;
			uint32_t        st_flags;
			uint32_t        st_gen;
			int32_t         st_lspare;
			int64_t         st_qspare[2];
		};
		int stat(const char* pathname, struct stat* statbuf) asm("stat$INODE64");
		int lstat(const char* pathname, struct stat* statbuf) asm("lstat$INODE64");

		struct dirent {
			uint32_t d_ino;
			uint16_t d_reclen;
			uint8_t  d_type;
			uint8_t  d_namlen;
			char     d_name[1024];
		};
	]])
end

pcall(ffi.cdef, [[
	typedef int64_t intptr_t;
	typedef uint64_t uintptr_t;

	struct kevent {
		uintptr_t ident;
		int16_t   filter;
		uint16_t  flags;
		uint32_t  fflags;
		intptr_t  data;
		void*     udata;
	};
]])

-- kqueue(2) and its vnode filter; the watcher built from them lives in
-- fs.raw.kqueue, which the BSD backend shares.
local O_EVTONLY    = 0x8000
local EVFILT_VNODE = -4

---@class fs.raw.macos: fs.raw.posix
local fs           = require("fs.raw.posix")(function(s, modeToStatType)
	return {
		size = s.st_size,
		modifyTime = s.st_mtimespec.tv_sec,
		accessTime = s.st_atimespec.tv_sec,
		type = modeToStatType[bit.band(s.st_mode, 0xF000)],
		mode = bit.band(s.st_mode, 0x1FF)
	}
end)

ffi.cdef([[
	int clonefile(const char* src, const char* dst, int flags);
]])

local posixCopyFile = fs.copyFile

--- Copy a file with clonefile(2): an instant copy-on-write clone on APFS
--- that shares data blocks with the source until either is modified.
--- clonefile refuses to replace an existing destination and only works on
--- APFS, so fall back to the POSIX read/write copy in both cases.
---@param src string
---@param dest string
---@return boolean
function fs.copyFile(src, dest)
	if ffi.C.clonefile(src, dest, 0) == 0 then
		return true
	end
	return posixCopyFile(src, dest)
end

-- kqueue(2) is the macOS watcher. Its descriptors are opened with O_EVTONLY so
-- that watching a file does not count as a reference that keeps it alive.
fs.watch = require("fs.raw.kqueue")(fs, EVFILT_VNODE, O_EVTONLY)

return fs

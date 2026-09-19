local ffi = require("ffi")

-- The stat structs below are built from struct timespec. fs.raw.posix declares
-- it too, but only opportunistically, since a platform backend may already have
-- declared it; the first declaration is the one that sticks, so declaring it
-- here the same way is safe either way.
pcall(ffi.cdef, [[
	struct timespec {
		long tv_sec;
		long tv_nsec;
	};
]])

ffi.cdef([[
	/* uname(3) fills a struct utsname, but only the leading, NUL-terminated
	   fields are read, so it is declared as plain bytes to stay independent of
	   the struct layout of each flavour. */
	int uname(char* buf);
]])

--- Room for a whole struct utsname: five fields, at most 256 bytes each.
local UTSNAME_SIZE = 4096

--- Width of one struct utsname field on NetBSD, its _SYS_NMLN, which is 256 in
--- 9.x, 10.x and 11.x alike. The fields are fixed-width arrays padded with
--- NULs, so the release is two fields along rather than after the first
--- terminator.
local NETBSD_NMLN = 256

--- Watchable descriptors are obtained with a plain read-only open on the BSDs:
--- O_EVTONLY, which watches without holding a reference to the file, is a macOS
--- flag. (A file that cannot be opened for reading cannot be watched.)
local O_RDONLY = 0

--- Reads the kernel name from uname(3), and NetBSD's release with it: which
--- kevent(2) entry point fs calls on NetBSD depends on the release, and no
--- other flavour needs a field past the name.
---@return string? name
---@return string? netbsdRelease
local function uname()
	local buf = ffi.new("char[?]", UTSNAME_SIZE)
	if ffi.C.uname(buf) ~= 0 then
		return nil, nil
	end

	local name = ffi.string(buf)
	if name ~= "NetBSD" then
		return name, nil
	end

	return name, ffi.string(buf + 2 * NETBSD_NMLN)
end

--- Every BSD names the members the posix layer reads the same way, so one
--- conversion serves all four flavours.
---@param s ffi.cdata*
---@param modeToStatType table<number, fs.Stat.Type>
---@return fs.Stat
local function rawToCrossStat(s, modeToStatType)
	return {
		size = s.st_size,
		modifyTime = s.st_mtim.tv_sec,
		accessTime = s.st_atim.tv_sec,
		type = modeToStatType[bit.band(s.st_mode, 0xF000)],
		mode = bit.band(s.st_mode, 0x1FF)
	}
end

local FREEBSD_ABI = [[
	typedef uint64_t dev_t;
	typedef uint64_t ino_t;
	typedef uint64_t nlink_t;
	typedef uint16_t mode_t;
	typedef uint32_t uid_t;
	typedef uint32_t gid_t;
	typedef int64_t  off_t;
	typedef int64_t  blkcnt_t;
	typedef int32_t  blksize_t;
	typedef uint32_t fflags_t;

	struct stat {            /* 224 */
		dev_t     st_dev;
		ino_t     st_ino;
		nlink_t   st_nlink;
		mode_t    st_mode;
		int16_t   st_bsdflags;
		uid_t     st_uid;
		gid_t     st_gid;
		int32_t   st_padding1;
		dev_t     st_rdev;
		struct timespec st_atim;
		struct timespec st_mtim;
		struct timespec st_ctim;
		struct timespec st_birthtim;
		off_t     st_size;
		blkcnt_t  st_blocks;
		blksize_t st_blksize;
		fflags_t  st_flags;
		uint64_t  st_gen;
		uint64_t  st_filerev;
		uint64_t  st_spare[9];
	};

	struct dirent {          /* 280, d_name at 24 */
		ino_t    d_fileno;
		off_t    d_off;
		uint16_t d_reclen;
		uint8_t  d_type;
		uint8_t  d_pad0;
		uint16_t d_namlen;
		uint16_t d_pad1;
		char     d_name[256];
	};

	/* 64: FreeBSD 12 grew the trailing ext[4], and the kernel copies
	   sizeof(struct kevent) per event, so it has to be declared. */
	struct kevent {
		uintptr_t ident;
		int16_t   filter;
		uint16_t  flags;
		uint32_t  fflags;
		int64_t   data;
		void*     udata;
		uint64_t  ext[4];
	};
]]

--- The part of the NetBSD block that every release shares.
local NETBSD_ABI = [[
	typedef uint64_t dev_t;
	typedef uint64_t ino_t;
	typedef uint32_t mode_t;
	typedef uint32_t nlink_t;
	typedef uint32_t uid_t;
	typedef uint32_t gid_t;
	typedef int64_t  off_t;
	typedef int64_t  blkcnt_t;
	typedef int32_t  blksize_t;
	typedef struct __dirstream DIR;

	struct stat {            /* 152 */
		dev_t     st_dev;
		mode_t    st_mode;
		ino_t     st_ino;
		nlink_t   st_nlink;
		uid_t     st_uid;
		gid_t     st_gid;
		dev_t     st_rdev;
		struct timespec st_atim;
		struct timespec st_mtim;
		struct timespec st_ctim;
		struct timespec st_birthtim;
		off_t     st_size;
		blkcnt_t  st_blocks;
		blksize_t st_blksize;
		uint32_t  st_flags;
		uint32_t  st_gen;
		uint32_t  st_spare[2];
	};

	struct dirent {          /* 528, d_name at 13 */
		ino_t    d_fileno;
		uint16_t d_reclen;
		uint16_t d_namlen;
		uint8_t  d_type;
		char     d_name[512];
	};

	/* NetBSD redirects these names in its headers to the symbols of the
	   current ABI: the plain names are compatibility entry points that fill
	   the older stat12 and dirent12 structs. They are declared here, ahead of
	   fs.raw.posix and its plain names, because the first declaration of a
	   symbol is the one that sticks. */
	int stat(const char* pathname, struct stat* statbuf) asm("__stat50");
	int lstat(const char* pathname, struct stat* statbuf) asm("__lstat50");
	DIR* opendir(const char* name) asm("__opendir30");
	struct dirent* readdir(DIR* dirp) asm("__readdir30");
]]

--- struct kevent before NetBSD 11.0: 40 bytes, behind __kevent50.
local NETBSD_KEVENT_10 = [[
	struct kevent {
		uintptr_t ident;
		uint32_t  filter;
		uint32_t  flags;
		uint32_t  fflags;
		int64_t   data;
		void*     udata;
	};

	int kevent(int kq, const struct kevent* changelist, int nchanges,
	           struct kevent* eventlist, int nevents, const struct timespec* timeout) asm("__kevent50");
]]

--- struct kevent from NetBSD 11.0 on: 72 bytes, behind __kevent100. A 40-byte
--- event list handed to the 11.0 entry point would be read mis-strided.
local NETBSD_KEVENT_11 = [[
	struct kevent {
		uintptr_t ident;
		uint32_t  filter;
		uint32_t  flags;
		uint32_t  fflags;
		int64_t   data;
		void*     udata;
		uint64_t  ext[4];
	};

	int kevent(int kq, const struct kevent* changelist, int nchanges,
	           struct kevent* eventlist, int nevents, const struct timespec* timeout) asm("__kevent100");
]]

local OPENBSD_ABI = [[
	typedef uint32_t mode_t;
	typedef int32_t  dev_t;
	typedef uint64_t ino_t;
	typedef uint32_t nlink_t;
	typedef uint32_t uid_t;
	typedef uint32_t gid_t;
	typedef int64_t  off_t;
	typedef int64_t  blkcnt_t;
	typedef int32_t  blksize_t;

	struct stat {            /* 128 */
		mode_t    st_mode;
		dev_t     st_dev;
		ino_t     st_ino;
		nlink_t   st_nlink;
		uid_t     st_uid;
		gid_t     st_gid;
		dev_t     st_rdev;
		struct timespec st_atim;
		struct timespec st_mtim;
		struct timespec st_ctim;
		off_t     st_size;
		blkcnt_t  st_blocks;
		blksize_t st_blksize;
		uint32_t  st_flags;
		uint32_t  st_gen;
		struct timespec __st_birthtim;
	};

	struct dirent {          /* 280, d_name at 24 */
		ino_t    d_fileno;
		int64_t  d_off;
		uint16_t d_reclen;
		uint8_t  d_type;
		uint8_t  d_namlen;
		uint8_t  __d_padding[4];
		char     d_name[256];
	};

	struct kevent {          /* 32 */
		uintptr_t ident;
		int16_t   filter;
		uint16_t  flags;
		uint32_t  fflags;
		int64_t   data;
		void*     udata;
	};
]]

local DRAGONFLY_ABI = [[
	typedef uint64_t ino_t;
	typedef uint32_t nlink_t;
	typedef uint32_t dev_t;
	typedef uint16_t mode_t;
	typedef uint32_t uid_t;
	typedef uint32_t gid_t;

	struct stat {            /* 128 */
		ino_t     st_ino;
		nlink_t   st_nlink;
		dev_t     st_dev;
		mode_t    st_mode;
		uint16_t  st_padding1;
		uid_t     st_uid;
		gid_t     st_gid;
		dev_t     st_rdev;
		struct timespec st_atim;
		struct timespec st_mtim;
		struct timespec st_ctim;
		int64_t   st_size;
		int64_t   st_blocks;
		uint32_t  __old_st_blksize;
		uint32_t  st_flags;
		uint32_t  st_gen;
		int32_t   st_lspare;
		int64_t   st_blksize;
		int64_t   st_qspare2;
	};

	struct dirent {          /* 272, d_name at 16 */
		ino_t    d_fileno;
		uint16_t d_namlen;
		uint8_t  d_type;
		uint8_t  d_unused1;
		uint32_t d_unused2;
		char     d_name[256];
	};

	struct kevent {          /* 32 */
		uintptr_t ident;
		int16_t   filter;
		uint16_t  flags;
		uint32_t  fflags;
		intptr_t  data;
		void*     udata;
	};
]]

--- struct kevent gained a trailing ext[4] in NetBSD 11.0, along with a new
--- entry point: a 40-byte event list handed to the 11.0 one would be read
--- mis-strided, so the release decides which pair to declare.
---@param release string? # uname release, such as "10.2" or "11.0_STABLE"
---@return string
local function netbsdKeventABI(release)
	local major = tonumber(tostring(release):match("^(%d+)"))

	if major == nil then
		error("Cannot determine the NetBSD release from uname: " .. tostring(release))
	end

	return major >= 11 and NETBSD_KEVENT_11 or NETBSD_KEVENT_10
end

local name, netbsdRelease = uname()

--- The ABI of each BSD flavour: the structs fs.raw.posix reads, and the
--- EVFILT_VNODE number its kqueue(2) uses. The declarations are transcribed
--- from <sys/stat.h>, <sys/dirent.h> and <sys/event.h> for the 64-bit (LP64)
--- ABI of amd64 and arm64, which lay these structs out identically.
---
--- The sizes in the comments are the ones the kernel writes, so a struct must
--- never be declared smaller than the real one.
local flavors = {
	FreeBSD = {
		vnodeFilter = -4,
		cdef = FREEBSD_ABI
	},
	NetBSD = {
		-- NetBSD has numbered its kqueue filters positively since before 6.0,
		-- unlike the FreeBSD numbering the other BSDs (and macOS) inherited.
		vnodeFilter = 3,
		-- Only the half every release shares; the kevent(2) half is appended
		-- below, once the release is known.
		cdef = NETBSD_ABI
	},
	OpenBSD = {
		vnodeFilter = -4,
		cdef = OPENBSD_ABI
	},
	DragonFly = {
		vnodeFilter = -4,
		cdef = DRAGONFLY_ABI
	}
}

local flavor = flavors[name]
if flavor == nil then
	error("Unsupported BSD flavor: " .. tostring(name))
end

-- Declared before fs.raw.posix loads, so that the flavour's symbols win over
-- the plain names that module declares.
local abi = flavor.cdef
if name == "NetBSD" then
	abi = abi .. netbsdKeventABI(netbsdRelease)
end

ffi.cdef(abi)

local posix = require("fs.raw.posix")

---@class fs.raw.bsd: fs.raw.posix
local fs = posix(rawToCrossStat)

-- Required only now, because its kevent(2) prototype refers to struct kevent,
-- which the ABI block above declares.
fs.watch = require("fs.raw.kqueue")(fs, flavor.vnodeFilter, O_RDONLY)

return fs

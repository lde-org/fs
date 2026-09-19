local ffi = require("ffi")

ffi.cdef([[
	typedef struct __dirstream DIR;
	DIR* opendir(const char* name);
	int closedir(DIR* dirp);
	int mkdir(const char* pathname, unsigned int mode);
	int symlink(const char* target, const char* linkpath);
	int chmod(const char* pathname, unsigned int mode);
]])

-- struct timespec may already be declared by the platform backend (macOS),
-- so this is optional.
pcall(ffi.cdef, [[
	struct timespec {
		long tv_sec;
		long tv_nsec;
	};
]])

ffi.cdef([[
	int open(const char* pathname, int flags, ...);
	long read(int fd, void* buf, size_t count);
	long write(int fd, const void* buf, size_t count);
	int close(int fd);
	int fchmod(int fd, unsigned int mode);
	int futimens(int fd, const struct timespec times[2]);
	int rename(const char* oldpath, const char* newpath);
	const char* strerror(int errnum);
]])

---@type table<number, fs.DirEntry.Type>
local dTypeToEntryType = {
	[0] = "unknown",
	[4] = "dir",
	[8] = "file",
	[10] = "symlink"
}

---@type table<number, fs.Stat.Type>
local modeToStatType = {
	[0x4000] = "dir",
	[0x8000] = "file",
	[0xA000] = "symlink"
}

-- open(2) flags differ between Linux and the BSDs (macOS included).
local O_RDONLY = 0
local O_WRONLY = 0x0001
local O_CREAT, O_TRUNC
if jit.os == "OSX" or jit.os == "BSD" then
	O_CREAT = 0x0200
	O_TRUNC = 0x0400
else
	O_CREAT = 0x0040
	O_TRUNC = 0x0200
end

--- Call after defining struct dirent and struct stat in ffi.
---@param rawToCrossStat fun(s: ffi.cdata*, modeToStatType: table<number, fs.Stat.Type>): fs.Stat
---@param dataCopier? fun(in_fd: number, out_fd: number, size: number): boolean # Kernel-level data copy from the current file offsets; falls back to a read/write loop
---@return fs.raw.posix
return function(rawToCrossStat, dataCopier)
	ffi.cdef([[
		struct dirent* readdir(DIR* dirp);
		int stat(const char* pathname, struct stat* statbuf);
		int lstat(const char* pathname, struct stat* statbuf);
	]])

	---@class fs.raw.posix: fs.raw
	local fs = {}

	local newStat = ffi.typeof("struct stat")

	local function rawStat(p)
		local buf = newStat()
		if ffi.C.stat(p, buf) ~= 0 then return nil end
		return buf
	end

	local function rawLstat(p)
		local buf = newStat()
		if ffi.C.lstat(p, buf) ~= 0 then return nil end
		return buf
	end

	---@param p string
	---@return (fun(): fs.DirEntry?)?
	function fs.readdir(p)
		local dir = ffi.C.opendir(p)
		if dir == nil then return nil end

		return function()
			while true do
				local entry = ffi.C.readdir(dir)
				if entry == nil then
					ffi.C.closedir(dir)
					return nil
				end

				local name = ffi.string(entry.d_name)
				if name ~= "." and name ~= ".." then
					return {
						name = name,
						type = dTypeToEntryType[entry.d_type] or "unknown"
					}
				end
			end
		end
	end

	---@param p string
	function fs.exists(p)
		return rawStat(p) ~= nil
	end

	---@param p string
	function fs.stat(p)
		local s = rawStat(p)
		if s == nil then return nil end
		return rawToCrossStat(s, modeToStatType)
	end

	---@param p string
	function fs.lstat(p)
		local s = rawLstat(p)
		if s == nil then return nil end
		return rawToCrossStat(s, modeToStatType)
	end

	---@param p string
	function fs.isdir(p)
		local s = rawStat(p)
		if s == nil then return false end
		return bit.band(s.st_mode, 0x4000) ~= 0
	end

	---@param p string
	function fs.isfile(p)
		local s = rawStat(p)
		if s == nil then return false end
		return bit.band(s.st_mode, 0x8000) ~= 0
	end

	---@param p string
	function fs.islink(p)
		local s = rawLstat(p)
		if s == nil then return false end
		return bit.band(s.st_mode, 0xA000) ~= 0
	end

	---@param p string
	function fs.mkdir(p)
		return ffi.C.mkdir(p, 511) == 0
	end

	---@param src string
	---@param dest string
	function fs.mklink(src, dest)
		return ffi.C.symlink(src, dest) == 0
	end

	---@param p string
	function fs.rmlink(p)
		return os.remove(p) ~= nil
	end

	---@param p string
	function fs.removeFile(p)
		return os.remove(p) ~= nil
	end

	---@param p string
	---@param mode number
	function fs.chmod(p, mode)
		return ffi.C.chmod(p, mode) == 0
	end

	-- Shared buffer for the read/write fallback; copyFile is not reentrant.
	local bufSize = 65536
	local buf = ffi.new("char[?]", bufSize)

	--- Copies data from inFd to outFd starting at their current offsets.
	---@param inFd number
	---@param outFd number
	---@return boolean
	local function manualCopy(inFd, outFd)
		while true do
			local n = ffi.C.read(inFd, buf, bufSize)
			if n < 0 then
				if ffi.errno() ~= 4 then return false end -- EINTR: retry
			elseif n == 0 then
				return true
			else
				local written = 0
				while written < n do
					local w = ffi.C.write(outFd, buf + written, n - written)
					if w < 0 then
						if ffi.errno() ~= 4 then return false end -- EINTR: retry
					else
						written = written + w
					end
				end
			end
		end
	end

	--- Copies a file's data plus its mode and timestamps.
	--- Uses the platform's kernel copy (dataCopier) when available, otherwise
	--- falls back to a read/write loop.
	---@param src string
	---@param dest string
	---@return boolean
	function fs.copyFile(src, dest)
		local st = fs.stat(src)
		if st == nil then return false end

		local inFd = ffi.C.open(src, O_RDONLY)
		if inFd < 0 then return false end

		-- O_WRONLY | O_CREAT | O_TRUNC, mode 0666 (masked by umask until fchmod)
		local outFd = ffi.C.open(dest, O_WRONLY + O_CREAT + O_TRUNC, ffi.cast("int", 0x1B6))
		if outFd < 0 then
			ffi.C.close(inFd)
			return false
		end

		-- Pcall dataCopier which might be missing or throw an error when it is an ffi symbol that may or may not be defined (ie, old kernel has no copy_file_range)
		local ok
		if dataCopier then
			local success, result = pcall(dataCopier, inFd, outFd, st.size or -1)
			ok = success and result
		end

		if not ok then
			ok = manualCopy(inFd, outFd)
		end
		if ok then
			-- Best effort: keep the source's mode and timestamps.
			ffi.C.fchmod(outFd, st.mode or 0x1A4) -- 0644
			local times = ffi.new("struct timespec[2]")
			times[0].tv_sec = st.accessTime or 0
			times[1].tv_sec = st.modifyTime or 0
			ffi.C.futimens(outFd, times)
		end

		ffi.C.close(inFd)
		ffi.C.close(outFd)
		return ok
	end


	--- Move a file or directory with rename.
	--- Fails on cross-device moves.
	---@param old string
	---@param new string
	---@return boolean
	---@return string? err
	function fs.moveFile(old, new)
		if ffi.C.rename(old, new) == 0 then return true end

		local errno = ffi.errno()
		if errno == 18 then return false, "exdev" end

		return false, "failed to move: " .. ffi.string(ffi.C.strerror(errno))
	end

	return fs
end

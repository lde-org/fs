local ffi = require("ffi")

ffi.cdef([[
	typedef void* HANDLE;
	typedef uint32_t DWORD;
	typedef uint16_t WORD;
	typedef unsigned char BYTE;
	typedef int BOOL;
	typedef unsigned short WCHAR;

	typedef struct {
		DWORD dwLowDateTime;
		DWORD dwHighDateTime;
	} FILETIME;

	typedef struct {
		DWORD dwFileAttributes;
		FILETIME ftCreationTime;
		FILETIME ftLastAccessTime;
		FILETIME ftLastWriteTime;
		DWORD nFileSizeHigh;
		DWORD nFileSizeLow;
		DWORD dwReserved0;
		DWORD dwReserved1;
		WCHAR cFileName[260];
		WCHAR cAlternateFileName[14];
	} WIN32_FIND_DATAW;

	int MultiByteToWideChar(unsigned int CodePage, DWORD dwFlags, const char* lpMultiByteStr, int cbMultiByte,
		WCHAR* lpWideCharStr, int cchWideChar);
	int WideCharToMultiByte(unsigned int CodePage, DWORD dwFlags, const WCHAR* lpWideCharStr, int cchWideChar,
		char* lpMultiByteStr, int cbMultiByte, const char* lpDefaultChar, BOOL* lpUsedDefaultChar);

	HANDLE FindFirstFileW(const WCHAR* lpFileName, WIN32_FIND_DATAW* lpFindFileData);
	BOOL FindNextFileW(HANDLE hFindFile, WIN32_FIND_DATAW* lpFindFileData);
	BOOL FindClose(HANDLE hFindFile);
	BOOL CreateDirectoryW(const WCHAR* lpPathName, void* lpSecurityAttributes);
	BOOL CreateSymbolicLinkW(const WCHAR* lpSymlinkFileName, const WCHAR* lpTargetFileName, DWORD dwFlags);
	DWORD GetFileAttributesW(const WCHAR* lpFileName);

	typedef struct {
		DWORD dwFileAttributes;
		FILETIME ftCreationTime;
		FILETIME ftLastAccessTime;
		FILETIME ftLastWriteTime;
		DWORD nFileSizeHigh;
		DWORD nFileSizeLow;
	} WIN32_FILE_ATTRIBUTE_DATA;

	BOOL GetFileAttributesExW(const WCHAR* lpFileName, int fInfoLevelClass, WIN32_FILE_ATTRIBUTE_DATA* lpFileInformation);

	HANDLE CreateFileW(
		const WCHAR* lpFileName,
		DWORD dwDesiredAccess,
		DWORD dwShareMode,
		void* lpSecurityAttributes,
		DWORD dwCreationDisposition,
		DWORD dwFlagsAndAttributes,
		HANDLE hTemplateFile
	);

	BOOL DeviceIoControl(
		HANDLE hDevice,
		DWORD dwIoControlCode,
		void* lpInBuffer,
		DWORD nInBufferSize,
		void* lpOutBuffer,
		DWORD nOutBufferSize,
		DWORD* lpBytesReturned,
		void* lpOverlapped
	);

	BOOL CloseHandle(HANDLE hObject);

	DWORD GetFullPathNameW(
		const WCHAR* lpFileName,
		DWORD nBufferLength,
		WCHAR* lpBuffer,
		WCHAR** lpFilePart
	);

	BOOL RemoveDirectoryW(const WCHAR* lpPathName);
	BOOL DeleteFileW(const WCHAR* lpFileName);
	BOOL MoveFileExW(const WCHAR* lpExistingFileName, const WCHAR* lpNewFileName, DWORD dwFlags);
	DWORD GetLastError(void);
	BOOL SetFileAttributesW(const WCHAR* lpFileName, DWORD dwFileAttributes);
	BOOL CreateHardLinkW(const WCHAR* lpFileName, const WCHAR* lpExistingFileName, void* lpSecurityAttributes);
	BOOL CopyFileW(const WCHAR* lpExistingFileName, const WCHAR* lpNewFileName, BOOL bFailIfExists);

	HANDLE CreateIoCompletionPort(HANDLE FileHandle, HANDLE ExistingCompletionPort,
	                              uintptr_t CompletionKey, DWORD NumberOfConcurrentThreads);
	BOOL ReadDirectoryChangesW(
		HANDLE hDirectory,
		void* lpBuffer,
		DWORD nBufferLength,
		BOOL bWatchSubtree,
		DWORD dwNotifyFilter,
		DWORD* lpBytesReturned,
		void* lpOverlapped,
		void* lpCompletionRoutine
	);
	BOOL GetOverlappedResult(HANDLE hFile, void* lpOverlapped, DWORD* lpNumberOfBytesTransferred, BOOL bWait);
	BOOL HasOverlappedIoCompleted(void* lpOverlapped);
]])

local kernel32 = ffi.load("kernel32")

local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", -1)
local INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
local FILE_ATTRIBUTE_READONLY = 0x1
local FILE_ATTRIBUTE_DIRECTORY = 0x10
local FILE_ATTRIBUTE_REPARSE_POINT = 0x400

-- Paths are UTF-8 on every platform. Windows takes and hands back names as UTF-16 through its wide
-- calls; the narrow ones read them in the system code page, which spells "Antônio" with the single
-- byte 0xF4 and cannot spell a name outside that code page at all. Every path crosses here.
local CP_UTF8 = 65001

--- A UTF-8 string as the NUL-terminated UTF-16 a wide call takes.
---@param s string
---@return ffi.cdata*
local function wide(s)
	local count = kernel32.MultiByteToWideChar(CP_UTF8, 0, s, #s, nil, 0)
	local buf = ffi.new("WCHAR[?]", count + 1)
	if count > 0 then kernel32.MultiByteToWideChar(CP_UTF8, 0, s, #s, buf, count) end
	return buf
end

--- UTF-16 from a wide call as UTF-8. `count` is in UTF-16 units; without it the string ends at NUL.
---@param w ffi.cdata*
---@param count number?
---@return string
local function narrow(w, count)
	count = count or -1
	local size = kernel32.WideCharToMultiByte(CP_UTF8, 0, w, count, nil, 0, nil, nil)
	if size <= 0 then return "" end
	local buf = ffi.new("char[?]", size)
	kernel32.WideCharToMultiByte(CP_UTF8, 0, w, count, buf, size, nil, nil)
	-- A NUL-terminated conversion counts the terminator in what it wrote.
	return ffi.string(buf, count == -1 and size - 1 or size)
end

-- The C runtime opens files by narrow path too -- `io.open`, `os.remove`, `os.rename`, and
-- `fopen` in a native module -- and reads that path in the code page its locale names. The
-- Universal CRT reads it as UTF-8 under a ".UTF8" locale, so the path a directory listing hands
-- over is the path `io.open` finds. Only the character type category is set: numbers and dates
-- keep formatting the way they did. A runtime older than the Universal CRT has no UTF-8 locale and
-- keeps its code page, and there a name outside ASCII cannot be opened through it.
do
	local ok, ucrt = pcall(ffi.load, "ucrtbase")
	if ok then
		pcall(ffi.cdef, [[ char* setlocale(int category, const char* locale); ]])
		local LC_CTYPE = 2
		pcall(function() return ucrt.setlocale(LC_CTYPE, ".UTF8") end)
	end
end

---@class fs.raw.windows: fs.raw
local fs = {}

---@param p string
---@return (fun(): fs.DirEntry?)?
function fs.readdir(p)
	local searchPath = p .. "\\*"

	local findData = ffi.new("WIN32_FIND_DATAW")

	local handle = kernel32.FindFirstFileW(wide(searchPath), findData)
	if handle == INVALID_HANDLE_VALUE then
		return nil
	end

	local first = true

	return function()
		while true do
			local hasNext
			if first then
				first = false
				hasNext = true
			else
				hasNext = kernel32.FindNextFileW(handle, findData) ~= 0
			end

			if not hasNext then
				kernel32.FindClose(handle)
				return nil
			end

			local name = narrow(findData.cFileName)
			if name ~= "." and name ~= ".." then
				local isDir = bit.band(findData.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY) ~= 0
				local isLink = bit.band(findData.dwFileAttributes, FILE_ATTRIBUTE_REPARSE_POINT) ~= 0

				local entryType
				if isLink then
					entryType = "symlink"
				elseif isDir then
					entryType = "dir"
				else
					entryType = "file"
				end

				return {
					name = name,
					type = entryType
				}
			end
		end
	end
end

---@param p string
local function getFileAttrs(p)
	local attrs = kernel32.GetFileAttributesW(wide(p))
	if attrs == INVALID_FILE_ATTRIBUTES then
		return nil
	end
	return attrs
end

--- Deletes a file, clearing the read-only attribute first if set.
--- DeleteFileW refuses read-only files, and git marks files read-only
--- inside .git on Windows.
---@param p string
---@return boolean
function fs.removeFile(p)
	local attrs = getFileAttrs(p)
	local w = wide(p)
	if attrs ~= nil and bit.band(attrs, FILE_ATTRIBUTE_READONLY) ~= 0 then
		kernel32.SetFileAttributesW(w, bit.band(attrs, bit.bnot(FILE_ATTRIBUTE_READONLY)))
	end
	return kernel32.DeleteFileW(w) ~= 0
end

--- Copy a file with CopyFileW, the kernel-mode copy used by the shell.
--- Overwrites an existing destination (bFailIfExists = FALSE).
---@param src string
---@param dest string
---@return boolean
function fs.copyFile(src, dest)
	return kernel32.CopyFileW(wide(src), wide(dest), 0) ~= 0
end

local MOVEFILE_REPLACE_EXISTING = 0x1
local MOVEFILE_COPY_ALLOWED = 0x2

--- Move a file or directory. MoveFileExW replaces existing files and handles
--- cross-volume moves natively (copy + delete in one kernel call), so there
--- is no cross-device fallback needed on Windows.
---@param old string
---@param new string
---@return boolean
---@return string? err
function fs.moveFile(old, new)
	if kernel32.MoveFileExW(wide(old), wide(new), MOVEFILE_REPLACE_EXISTING + MOVEFILE_COPY_ALLOWED) ~= 0 then
		return true
	end
	return false, "failed to move: error " .. tostring(kernel32.GetLastError())
end

local GENERIC_WRITE = 0x40000000
local OPEN_EXISTING = 3
local FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
local FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
local FSCTL_SET_REPARSE_POINT = 0x000900A4
local IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003

--- Get a path's attributes, following reparse points (junctions/symlinks).
--- GetFileAttributesW reports the link itself without following, so a dangling
--- link would look like a valid entry; opening through the link (without
--- FILE_FLAG_OPEN_REPARSE_POINT) fails when its target is gone. This matches
--- the POSIX stat()-based semantics the other backends expose.
---@param p string
local function getResolvedAttrs(p)
	local attrs = getFileAttrs(p)
	if attrs == nil then return nil end
	if bit.band(attrs, FILE_ATTRIBUTE_REPARSE_POINT) ~= 0 then
		local h = kernel32.CreateFileW(wide(p), 0, 0x7, nil, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nil)
		if h == INVALID_HANDLE_VALUE then return nil end
		kernel32.CloseHandle(h)
	end
	return attrs
end

---@param p string
---@return boolean
function fs.exists(p)
	return getResolvedAttrs(p) ~= nil
end

---@param p string
function fs.isdir(p)
	local attrs = getResolvedAttrs(p)
	if attrs == nil then
		return false
	end

	return bit.band(attrs, FILE_ATTRIBUTE_DIRECTORY) ~= 0
end

---@param p string
function fs.mkdir(p)
	return kernel32.CreateDirectoryW(wide(p), nil) ~= 0
end

--- Resolves a path to an absolute path using Win32 GetFullPathNameW: the UTF-16 it returns and
--- its length in units.
---@param p string
---@return ffi.cdata*? path
---@return number? length
local function getFullPath(p)
	local buf = ffi.new("WCHAR[?]", 1024)
	local len = kernel32.GetFullPathNameW(wide(p), 1024, buf, nil)
	if len == 0 or len >= 1024 then
		return nil
	end
	return buf, len
end

--- Creates an NTFS junction point (directory only).
--- Junctions do not require elevated privileges, unlike symlinks.
---@param src string # Target directory (must be absolute or will be resolved)
---@param dest string # Junction path to create
---@return boolean
local function createJunction(src, dest)
	-- Junctions require an absolute target path
	local absTarget, absLength = getFullPath(src)
	if not absTarget then
		return false
	end

	-- Create the junction directory
	local destW = wide(dest)
	if kernel32.CreateDirectoryW(destW, nil) == 0 then
		return false
	end

	-- Build the NT path as UTF-16LE: \??\C:\path\to\target
	local targetBytes = "\\\0?\0?\0\\\0" .. ffi.string(absTarget, absLength * 2)
	local targetByteLen = #targetBytes

	-- Build REPARSE_DATA_BUFFER for mount point (junction)
	-- Layout:
	--   DWORD ReparseTag
	--   WORD  ReparseDataLength
	--   WORD  Reserved
	--   WORD  SubstituteNameOffset
	--   WORD  SubstituteNameLength
	--   WORD  PrintNameOffset
	--   WORD  PrintNameLength
	--   WCHAR PathBuffer[...]  (SubstituteName + NUL + PrintName + NUL)
	local pathBufSize = targetByteLen + 2 + 2 -- substitute name + NUL + print name (empty) + NUL
	local reparseDataLen = 8 + pathBufSize -- 4 WORDs (8 bytes) + path buffer
	local totalSize = 8 + reparseDataLen   -- header (tag + length + reserved) + data

	local buf = ffi.new("uint8_t[?]", totalSize)
	local ptr = ffi.cast("uint8_t*", buf)

	-- ReparseTag (DWORD)
	ffi.cast("uint32_t*", ptr)[0] = IO_REPARSE_TAG_MOUNT_POINT
	-- ReparseDataLength (WORD)
	ffi.cast("uint16_t*", ptr + 4)[0] = reparseDataLen
	-- Reserved (WORD)
	ffi.cast("uint16_t*", ptr + 6)[0] = 0
	-- SubstituteNameOffset (WORD)
	ffi.cast("uint16_t*", ptr + 8)[0] = 0
	-- SubstituteNameLength (WORD) - without null terminator
	ffi.cast("uint16_t*", ptr + 10)[0] = targetByteLen
	-- PrintNameOffset (WORD) - after substitute name + null terminator
	ffi.cast("uint16_t*", ptr + 12)[0] = targetByteLen + 2
	-- PrintNameLength (WORD) - empty print name
	ffi.cast("uint16_t*", ptr + 14)[0] = 0

	-- PathBuffer: substitute name
	ffi.copy(ptr + 16, targetBytes, targetByteLen)
	-- Null terminator for substitute name (2 bytes)
	ffi.cast("uint16_t*", ptr + 16 + targetByteLen)[0] = 0
	-- Null terminator for print name (2 bytes)
	ffi.cast("uint16_t*", ptr + 16 + targetByteLen + 2)[0] = 0

	-- Open the junction directory with reparse point access
	---@type HANDLE
	local handle = kernel32.CreateFileW(
		destW,
		GENERIC_WRITE,
		0,
		nil,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS + FILE_FLAG_OPEN_REPARSE_POINT,
		nil
	)

	if handle == INVALID_HANDLE_VALUE then
		kernel32.RemoveDirectoryW(destW)
		return false
	end

	local bytesReturned = ffi.new("DWORD[1]")
	local ok = kernel32.DeviceIoControl(
		handle,
		FSCTL_SET_REPARSE_POINT,
		buf,
		totalSize,
		nil,
		0,
		bytesReturned,
		nil
	)

	kernel32.CloseHandle(handle)

	if ok == 0 then
		kernel32.RemoveDirectoryW(destW)
		return false
	end

	return true
end

--- Removes a symlink or junction without following it.
---@param p string
---@return boolean
function fs.rmlink(p)
	local attrs = getFileAttrs(p)
	if attrs ~= nil and bit.band(attrs, FILE_ATTRIBUTE_DIRECTORY) ~= 0 then
		return kernel32.RemoveDirectoryW(wide(p)) ~= 0
	end
	return kernel32.DeleteFileW(wide(p)) ~= 0
end

---@param src string
---@param dest string
function fs.mklink(src, dest)
	if fs.isdir(src) then
		return createJunction(src, dest)
	end

	local srcW, destW = wide(src), wide(dest)
	if kernel32.CreateSymbolicLinkW(destW, srcW, 0x2) ~= 0 then
		return true
	end
	return kernel32.CreateHardLinkW(destW, srcW, nil) ~= 0
end

---@param p string
function fs.islink(p)
	local attrs = getFileAttrs(p)
	if attrs == nil then
		return false
	end

	return bit.band(attrs, FILE_ATTRIBUTE_REPARSE_POINT) ~= 0
end

---@param p string
function fs.isfile(p)
	local attrs = getResolvedAttrs(p)
	if attrs == nil then
		return false
	end

	return bit.band(attrs, FILE_ATTRIBUTE_DIRECTORY) == 0
end

-- FILETIME is 100ns intervals since 1601-01-01. Unix epoch is 1970-01-01.
-- Difference: 11644473600 seconds = 116444736000000000 in 100ns units.
local EPOCH_DIFF = 116444736000000000ULL

---@param ft { dwLowDateTime: number, dwHighDateTime: number }
local function filetimeToUnix(ft)
	local ticks = ffi.cast("uint64_t", ft.dwHighDateTime) * 0x100000000ULL + ft.dwLowDateTime
	return assert(tonumber((ticks - EPOCH_DIFF) / 10000000ULL))
end

---@param attrs number
---@return fs.Stat.Type
local function attrsToType(attrs)
	if bit.band(attrs, FILE_ATTRIBUTE_REPARSE_POINT) ~= 0 then
		return "symlink"
	elseif bit.band(attrs, FILE_ATTRIBUTE_DIRECTORY) ~= 0 then
		return "dir"
	else
		return "file"
	end
end

local newFileAttrData = ffi.typeof("WIN32_FILE_ATTRIBUTE_DATA")

---@param s WIN32_FILE_ATTRIBUTE_DATA
local function fileSize(s)
	return assert(tonumber(s.nFileSizeHigh)) * 0x100000000 + assert(tonumber(s.nFileSizeLow))
end

---@param s WIN32_FILE_ATTRIBUTE_DATA
---@param type fs.Stat.Type
---@return fs.Stat
local function rawToCrossStat(s, type)
	return {
		size = fileSize(s),
		accessTime = filetimeToUnix(s.ftLastAccessTime),
		modifyTime = filetimeToUnix(s.ftLastWriteTime),
		type = type
	}
end

---@param p string
---@return fs.Stat?
function fs.stat(p)
	-- Follow reparse points so a dangling junction/symlink reports as missing.
	if getResolvedAttrs(p) == nil then
		return nil
	end
	local data = newFileAttrData()
	if kernel32.GetFileAttributesExW(wide(p), 0, data) == 0 then
		return nil
	end

	local type = bit.band(data.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY) ~= 0 and "dir" or "file"
	return rawToCrossStat(data, type)
end

---@param p string
---@return fs.Stat?
function fs.lstat(p)
	local data = newFileAttrData()
	if kernel32.GetFileAttributesExW(wide(p), 0, data) == 0 then
		return nil
	end

	return rawToCrossStat(data, attrsToType(data.dwFileAttributes))
end

---@alias fs.WatchEvent "create" | "modify" | "delete" | "rename"

---@class fs.Watcher
---@field close fun()
---@field poll fun()

local FILE_LIST_DIRECTORY           = 0x0001
local FILE_SHARE_READ               = 0x00000001
local FILE_SHARE_WRITE              = 0x00000002
local FILE_SHARE_DELETE             = 0x00000004
local OPEN_EXISTING_W               = 3
local FILE_FLAG_BACKUP_SEMANTICS_W  = 0x02000000
local FILE_FLAG_OVERLAPPED          = 0x40000000

local FILE_NOTIFY_CHANGE_FILE_NAME  = 0x00000001
local FILE_NOTIFY_CHANGE_DIR_NAME   = 0x00000002
local FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
local FILE_NOTIFY_CHANGE_SIZE       = 0x00000008

local FILE_ACTION_ADDED             = 1
local FILE_ACTION_REMOVED           = 2
local FILE_ACTION_MODIFIED          = 3
local FILE_ACTION_RENAMED_OLD       = 4
local FILE_ACTION_RENAMED_NEW       = 5

ffi.cdef([[
	typedef struct {
		uintptr_t Internal;
		uintptr_t InternalHigh;
		DWORD Offset;
		DWORD OffsetHigh;
		HANDLE hEvent;
	} OVERLAPPED_W;

	HANDLE CreateEventA(void* lpEventAttributes, BOOL bManualReset, BOOL bInitialState, const char* lpName);
	DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
]])

local WAIT_OBJECT_0 = 0

--- Watch a directory for changes. Calls callback(event, name) for each change.
--- Returns a watcher with :poll() (non-blocking), :wait() (blocking), and :close().
---@param p string
---@param callback fun(event: fs.WatchEvent, name: string)
---@param opts { recursive: boolean? }?
---@return fs.Watcher?
function fs.watch(p, callback, opts)
	local recursive = opts and opts.recursive or false

	local handle = kernel32.CreateFileW(
		wide(p),
		FILE_LIST_DIRECTORY,
		bit.bor(FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE),
		nil,
		OPEN_EXISTING_W,
		bit.bor(FILE_FLAG_BACKUP_SEMANTICS_W, FILE_FLAG_OVERLAPPED),
		nil
	)
	if handle == INVALID_HANDLE_VALUE then return nil end

	---@type fun(a: any, b: number, c: number, d: string?): HANDLE
	local createEvent = kernel32.CreateEventA
	---@type HANDLE
	local event = createEvent(nil, 1, 0, nil) -- manual reset, initially unsignaled
	if event == nil then
		kernel32.CloseHandle(handle); return nil
	end

	local bufSize = 4096
	local buf = ffi.new("uint8_t[?]", bufSize)
	local overlapped = ffi.new("OVERLAPPED_W[1]")
	overlapped[0].hEvent = event
	local bytesReturned = ffi.new("DWORD[1]")

	local notifyFilter = bit.bor(
		FILE_NOTIFY_CHANGE_FILE_NAME,
		FILE_NOTIFY_CHANGE_DIR_NAME,
		FILE_NOTIFY_CHANGE_LAST_WRITE,
		FILE_NOTIFY_CHANGE_SIZE
	)

	local function issueRead()
		ffi.fill(overlapped, assert(ffi.sizeof("OVERLAPPED_W")))
		overlapped[0].hEvent = event
		kernel32.ReadDirectoryChangesW(handle, buf, bufSize, recursive and 1 or 0, notifyFilter, bytesReturned,
			overlapped, nil)
	end

	issueRead()

	local INFINITE = 0xFFFFFFFF

	local function drain()
		local transferred = ffi.new("DWORD[1]")
		if kernel32.GetOverlappedResult(handle, overlapped, transferred, 0) == 0 then
			issueRead(); return
		end

		local n = tonumber(transferred[0])
		if not n or n == 0 then
			issueRead(); return
		end

		-- FILE_NOTIFY_INFORMATION: NextEntryOffset(4), Action(4), FileNameLength(4), FileName[...]
		local i = 0
		while i < n do
			local ptr     = buf + i
			local nextOff = ffi.cast("uint32_t*", ptr)[0]
			local action  = ffi.cast("uint32_t*", ptr + 4)[0]
			local nameLen = ffi.cast("uint32_t*", ptr + 8)[0]
			local name    = narrow(ffi.cast("WCHAR*", ptr + 12), nameLen / 2)

			local ev ---@type fs.WatchEvent
			if action == FILE_ACTION_ADDED then
				ev = "create"
			elseif action == FILE_ACTION_REMOVED then
				ev = "delete"
			elseif action == FILE_ACTION_MODIFIED then
				ev = "modify"
			elseif action == FILE_ACTION_RENAMED_OLD or action == FILE_ACTION_RENAMED_NEW then
				ev = "rename"
			end

			if ev then callback(ev, name) end
			if nextOff == 0 then break end
			i = i + nextOff
		end

		issueRead()
	end

	---@type fun(h: HANDLE, milliseconds: number): number
	local waitFor = kernel32.WaitForSingleObject

	---@type fs.Watcher
	local watcher = {}

	function watcher.poll()
		if waitFor(event, 0) ~= WAIT_OBJECT_0 then return end
		drain()
	end

	function watcher.wait()
		waitFor(event, INFINITE)
		drain()
	end

	function watcher.close()
		kernel32.CloseHandle(event)
		kernel32.CloseHandle(handle)
	end

	return watcher
end

return fs

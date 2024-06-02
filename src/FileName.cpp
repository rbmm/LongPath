#include "stdafx.h"

_NT_BEGIN

EXTERN_C_START

NTSYSAPI
NTSTATUS
NTAPI
RtlGetLastNtStatus();

NTSYSAPI
NTSTATUS
NTAPI
NtAlertThread(_In_ HANDLE hThread);

NTSYSAPI
NTSTATUS
NTAPI
NtDelayExecution(_In_ BOOLEAN Alertable, _In_ PLARGE_INTEGER Interval);

EXTERN_C_END

inline HANDLE fixH(HANDLE hFile)
{
	return hFile == INVALID_HANDLE_VALUE ? 0 : hFile;
}

HRESULT NTAPI GetLastErrorEx(ULONG dwError = GetLastError())
{
	NTSTATUS status = RtlGetLastNtStatus();
	return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

int ShowErrorBox(HWND hwnd, HRESULT dwError, PCWSTR lpCaption, UINT uType)
{
	int r = 0;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
	__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		lpSource = GetModuleHandle(L"ntdll");
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBoxW(hwnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

HRESULT CopySelf(POBJECT_ATTRIBUTES to)
{
	NTSTATUS status = STATUS_NO_MEMORY;

	if (PWSTR buf = new WCHAR[MINSHORT])
	{
		if (NOERROR == (status = (GetModuleFileNameW(0, buf, MINSHORT), GetLastError())))
		{
			if (HANDLE hFile = fixH(CreateFileW(buf, FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)))
			{
				IO_STATUS_BLOCK iosb;
				FILE_STANDARD_INFORMATION fsi;
				if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
				{
					if (fsi.EndOfFile.QuadPart)
					{
						HANDLE hFileTo;
						if (0 <= (status = NtCreateFile(&hFileTo, FILE_APPEND_DATA | SYNCHRONIZE, to, &iosb, &fsi.EndOfFile,
							FILE_ATTRIBUTE_TEMPORARY, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0)))
						{
							ULONG Bytes;

							do
							{
								Bytes = MINSHORT * sizeof(WCHAR);

								if ((ULONGLONG)fsi.EndOfFile.QuadPart < Bytes)
								{
									Bytes = fsi.EndOfFile.LowPart;
								}

								if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, buf, Bytes, 0, 0)))
								{
									break;
								}

								if (iosb.Information != Bytes)
								{
									status = STATUS_INTERNAL_ERROR;
									break;
								}

								if (0 > (status = NtWriteFile(hFileTo, 0, 0, 0, &iosb, buf, Bytes, 0, 0)))
								{
									break;
								}

								if (iosb.Information != Bytes)
								{
									status = STATUS_INTERNAL_ERROR;
									break;
								}

							} while (fsi.EndOfFile.QuadPart -= Bytes);

							NtClose(hFileTo);
						}
					}
				}

				NtClose(hFile);
			}
			else
			{
				status = GetLastErrorEx();
			}
		}

		delete[] buf;
	}

	return status;
}

HRESULT CopyDeep()
{
	ULONG cch = MINSHORT / 2 - 0x1000;
	NTSTATUS status = STATUS_NO_MEMORY;

	if (PWSTR buf = new WCHAR[cch])
	{
		static const WCHAR global[] = L"\\??\\";

		memcpy(buf, global, sizeof(global) - sizeof(WCHAR));
		PWSTR psz = buf + _countof(global) - 1;
		cch -= _countof(global) - 1;

		if (ULONG len = GetEnvironmentVariableW(L"tmp", psz, cch))
		{
			if (len + 2 < cch)
			{
				psz += len, cch -= len;

				PWSTR pc = psz;

				UNICODE_STRING ObjectName = { 0, 0, buf };
				OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

				goto __0;
				while (0x102 < cch)
				{
					RtlFillMemoryUlong(psz, 0x100 * sizeof(WCHAR), ('.' << 16) + '.');
					*psz = '\\', psz += 0x100, cch -= 0x100;

				__0:
					ObjectName.MaximumLength = ObjectName.Length = (USHORT)RtlPointerToOffset(buf, psz);
					IO_STATUS_BLOCK iosb;
					HANDLE hFile;
					if (0 > (status = NtCreateFile(&hFile, SYNCHRONIZE, &oa, &iosb, 0, 0,
						FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0)))
					{
						break;
					}

					NtClose(hFile);
				}

				*psz++ = '\\';
				*psz++ = '!';

				if (0 <= status)
				{
					ObjectName.MaximumLength = ObjectName.Length += 2 * sizeof(WCHAR);
					if (S_OK == (status = CopySelf(&oa)))
					{
						*psz = 0;
						STARTUPINFOW si{ sizeof(si) };
						PROCESS_INFORMATION pi;
						buf[1] = '\\';
						if (CreateProcessW(buf, const_cast<PWSTR>(L"\n"), 0, 0, 0, 0, 0, 0, &si, &pi))
						{
							ShowErrorBox(0, S_OK, L"!", MB_ICONINFORMATION);
							NtAlertThread(pi.hThread);
							NtClose(pi.hThread);
							WaitForSingleObject(pi.hProcess, INFINITE);
							NtClose(pi.hProcess);
						}
						else
						{
							status = GetLastErrorEx();
						}
						buf[1] = '?';
						*psz++ = '\\';
					}
				}

				while (pc < --psz)
				{
					if ('\\' == *psz)
					{
						ObjectName.MaximumLength = ObjectName.Length = (USHORT)RtlPointerToOffset(buf, psz);
						if (0 > ZwDeleteFile(&oa))
						{
							break;
						}
					}
				}
			}
		}
		else
		{
			status = GetLastErrorEx();
		}

		delete[] buf;
	}

	return status;
}


void WINAPI ep(void* )
{
	if ('\n' == *GetCommandLineW())
	{
		LARGE_INTEGER li = { 0, MINLONG };
		NtDelayExecution(TRUE, &li);
	}
	else
	{
		if (HRESULT hr = CopyDeep())
		{
			ShowErrorBox(0, hr, 0, MB_ICONERROR);
		}
	}

	ExitProcess(0);
}

_NT_END
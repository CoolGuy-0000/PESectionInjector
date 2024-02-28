#include <Windows.h>
#include <stdio.h>

typedef long long int QWORD;

BOOL CheckCG_Sig(PIMAGE_DOS_HEADER dos){
	return (*(DWORD*)((QWORD)dos + 2) == 0x69696763);
}

PIMAGE_SECTION_HEADER PEF_LastSection(PIMAGE_NT_HEADERS64 nt64) {
	return (PIMAGE_SECTION_HEADER)((QWORD)nt64 + sizeof(IMAGE_NT_HEADERS64) +
		((nt64->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER)));
}

PIMAGE_SECTION_HEADER PEF_LastSectionTail(PIMAGE_NT_HEADERS64 nt64) {
	return (PIMAGE_SECTION_HEADER)((QWORD)nt64 + sizeof(IMAGE_NT_HEADERS64) +
		(nt64->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
}

int main(int argc, char* argv[]) {

	if (argc != 3) {
		printf("cgpi <��ǥ ����> <BIN ����>\n");
		return -1;
	}

	HANDLE hTargetFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTargetFile == INVALID_HANDLE_VALUE) {
		printf("����: %s �� �ν��� �� ����\n", argv[1]);
		return -1;
	}
	
	HANDLE hBinFile = CreateFileA(argv[2], GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hBinFile == INVALID_HANDLE_VALUE) {
		printf("����: %s �� �ν��� �� ����\n", argv[2]);
		return -1;
	}

	DWORD filesize = GetFileSize(hTargetFile, 0);

	PVOID buffer = VirtualAlloc(NULL, filesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer) {
		printf("����: ���۸� ������ �� ����\n");
		return -1;
	}
	else if (!ReadFile(hTargetFile, buffer, filesize, 0, 0)) {
		printf("����: ������ ���� �� ����\n");
		return -1;
	}



	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;

	if (CheckCG_Sig(dos)) {
		printf("����: ������ ������ ���������� �ֽ��ϴ�!\n");
		return -1;
	}

	PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)((QWORD)dos + dos->e_lfanew);

	if (nt64->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)) {
		printf("����: PE+ �� ������\n");
		return -1;
	}

	char bk_file[256];

	_snprintf_s(bk_file, sizeof(bk_file), "%s.bk", argv[1]);
	bk_file[255] = 0;

	HANDLE hBKFile = CreateFileA(bk_file, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hBKFile == INVALID_HANDLE_VALUE) {
		printf("����: ��� ������ ���� �� �����ϴ�!\n");
		return -1;
	}

	WriteFile(hBKFile, buffer, filesize, 0, 0);
	CloseHandle(hBKFile);


	DWORD bin_filesize = GetFileSize(hBinFile, 0);

	PIMAGE_SECTION_HEADER cg_section = PEF_LastSectionTail(nt64);
	PIMAGE_SECTION_HEADER last_section = PEF_LastSection(nt64);

	DWORD newVA = (((last_section->VirtualAddress + last_section->Misc.VirtualSize)/nt64->OptionalHeader.SectionAlignment) + 1)*nt64->OptionalHeader.SectionAlignment;
	DWORD VA_Size = bin_filesize + nt64->OptionalHeader.SectionAlignment - (bin_filesize%nt64->OptionalHeader.SectionAlignment);
	DWORD RAW_Size = bin_filesize + nt64->OptionalHeader.FileAlignment - (bin_filesize%nt64->OptionalHeader.FileAlignment);
	
	memcpy(cg_section->Name, "cginit", sizeof("cginit"));
	
	cg_section->PointerToRawData = filesize;
	cg_section->SizeOfRawData = RAW_Size;

	cg_section->PointerToLinenumbers = 0;
	cg_section->NumberOfLinenumbers = 0;
	
	cg_section->PointerToRelocations = 0;
	cg_section->NumberOfRelocations = 0;

	cg_section->VirtualAddress = newVA;
	cg_section->Misc.VirtualSize = VA_Size;
	cg_section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	DWORD* cg_sig = (DWORD*)((QWORD)dos + 2);
	*cg_sig = 0x69696763; //cgii

	QWORD* some_infos = (QWORD*)((QWORD)dos + 6);
	*some_infos = nt64->OptionalHeader.AddressOfEntryPoint;

	nt64->FileHeader.NumberOfSections += 1;
	nt64->OptionalHeader.SizeOfImage += cg_section->Misc.VirtualSize;
	nt64->OptionalHeader.AddressOfEntryPoint = cg_section->VirtualAddress;

	PVOID bin_buffer = VirtualAlloc(NULL, cg_section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!bin_buffer) {
		printf("����: ���۸� ������ �� ����\n");
		return -1;
	}
	else if (!ReadFile(hBinFile, bin_buffer, cg_section->SizeOfRawData, 0, 0)) {
		printf("����: ������ ���� �� ����\n");
		return -1;
	}

	SetFilePointer(hTargetFile, 0, 0, FILE_END);
	WriteFile(hTargetFile, bin_buffer, cg_section->SizeOfRawData, 0, 0);

	SetFilePointer(hTargetFile, 0, 0, FILE_BEGIN);
	WriteFile(hTargetFile, buffer, filesize, 0, 0);

	CloseHandle(hBinFile);
	CloseHandle(hTargetFile);
	return 0;
}
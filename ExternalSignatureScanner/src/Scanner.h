#pragma once

/*
Is going to read every memory address that is MEM_COMMIT and !PAGE_NOACCESS of the targeted process by procId
*/
void scanFullMemory(DWORD procId);
#pragma once

extern "C" {
int GetRowCount();
void SqlHandleFree();
bool SqlHandler(LPCWSTR stringPath);
bool ReadTable(const char* tableName);
BYTE* GetValue(int rowNum, int field, DWORD* size);
}
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include "odbctrac.h"


HINSTANCE mHinst, mHinstDLL;
FARPROC mProcs[123];

LPCSTR mImportNames[] = {
	"FireVSDebugEvent", "TraceCloseLogFile", "TraceOpenLogFile", "TraceReturn", 
	"TraceSQLAllocConnect", "TraceSQLAllocEnv", "TraceSQLAllocHandle", "TraceSQLAllocHandleStd", 
	"TraceSQLAllocHandleStdW", "TraceSQLAllocStmt", "TraceSQLBindCol", "TraceSQLBindParam", 
	"TraceSQLBindParameter", "TraceSQLBrowseConnect", "TraceSQLBrowseConnectW", "TraceSQLBulkOperations", 
	"TraceSQLCancel", "TraceSQLCancelHandle", "TraceSQLCloseCursor", "TraceSQLColAttribute", 
	"TraceSQLColAttributes", "TraceSQLColAttributesW", "TraceSQLColAttributeW", "TraceSQLColumnPrivileges", 
	"TraceSQLColumnPrivilegesW", "TraceSQLColumns", "TraceSQLColumnsW", "TraceSQLConnect", 
	"TraceSQLConnectW", "TraceSQLCopyDesc", "TraceSQLDataSources", "TraceSQLDataSourcesW", 
	"TraceSQLDescribeCol", "TraceSQLDescribeColW", "TraceSQLDescribeParam", "TraceSQLDisconnect", 
	"TraceSQLDriverConnect", "TraceSQLDriverConnectW", "TraceSQLDrivers", "TraceSQLDriversW", 
	"TraceSQLEndTran", "TraceSQLError", "TraceSQLErrorW", "TraceSQLExecDirect", 
	"TraceSQLExecDirectW", "TraceSQLExecute", "TraceSQLExtendedFetch", "TraceSQLFetch", 
	"TraceSQLFetchScroll", "TraceSQLForeignKeys", "TraceSQLForeignKeysW", "TraceSQLFreeConnect", 
	"TraceSQLFreeEnv", "TraceSQLFreeHandle", "TraceSQLFreeStmt", "TraceSQLGetConnectAttr", 
	"TraceSQLGetConnectAttrW", "TraceSQLGetConnectOption", "TraceSQLGetConnectOptionW", "TraceSQLGetCursorName", 
	"TraceSQLGetCursorNameW", "TraceSQLGetData", "TraceSQLGetDescField", "TraceSQLGetDescFieldW", 
	"TraceSQLGetDescRec", "TraceSQLGetDescRecW", "TraceSQLGetDiagField", "TraceSQLGetDiagFieldW", 
	"TraceSQLGetDiagRec", "TraceSQLGetDiagRecW", "TraceSQLGetEnvAttr", "TraceSQLGetFunctions", 
	"TraceSQLGetInfo", "TraceSQLGetInfoW", "TraceSQLGetStmtAttr", "TraceSQLGetStmtAttrW", 
	"TraceSQLGetStmtOption", "TraceSQLGetTypeInfo", "TraceSQLGetTypeInfoW", "TraceSQLMoreResults", 
	"TraceSQLNativeSql", "TraceSQLNativeSqlW", "TraceSQLNumParams", "TraceSQLNumResultCols", 
	"TraceSQLParamData", "TraceSQLParamOptions", "TraceSQLPrepare", "TraceSQLPrepareW", 
	"TraceSQLPrimaryKeys", "TraceSQLPrimaryKeysW", "TraceSQLProcedureColumns", "TraceSQLProcedureColumnsW", 
	"TraceSQLProcedures", "TraceSQLProceduresW", "TraceSQLPutData", "TraceSQLRowCount", 
	"TraceSQLSetConnectAttr", "TraceSQLSetConnectAttrW", "TraceSQLSetConnectOption", "TraceSQLSetConnectOptionW", 
	"TraceSQLSetCursorName", "TraceSQLSetCursorNameW", "TraceSQLSetDescField", "TraceSQLSetDescFieldW", 
	"TraceSQLSetDescRec", "TraceSQLSetEnvAttr", "TraceSQLSetParam", "TraceSQLSetPos", 
	"TraceSQLSetScrollOptions", "TraceSQLSetStmtAttr", "TraceSQLSetStmtAttrW", "TraceSQLSetStmtOption", 
	"TraceSQLSpecialColumns", "TraceSQLSpecialColumnsW", "TraceSQLStatistics", "TraceSQLStatisticsW", 
	"TraceSQLTablePrivileges", "TraceSQLTablePrivilegesW", "TraceSQLTables", "TraceSQLTablesW", 
	"TraceSQLTransact", "TraceVersion", "TraceVSControl", 
};

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {
	mHinst = hinstDLL;
	if ( fdwReason == DLL_PROCESS_ATTACH ) {
		char sysdir[255], path[255];
		GetSystemDirectory( sysdir, 254 );
		sprintf( path, "%s\\odbctrac.dll", sysdir );
		mHinstDLL = LoadLibrary( path );
		if ( !mHinstDLL )
			return ( FALSE );

		for ( int i = 0; i < 123; i++ )
			mProcs[ i ] = GetProcAddress( mHinstDLL, mImportNames[ i ] );
	} else if ( fdwReason == DLL_PROCESS_DETACH ) {
		FreeLibrary( mHinstDLL );
	}
	return ( TRUE );
}

// FireVSDebugEvent
int __stdcall _FireVSDebugEvent() {
	return call_FireVSDebugEvent();
}

// TraceCloseLogFile
int __stdcall _TraceCloseLogFile() {
	return call_TraceCloseLogFile();
}

// TraceOpenLogFile
int __stdcall _TraceOpenLogFile() {
	return call_TraceOpenLogFile();
}

// TraceReturn
int __stdcall _TraceReturn() {
	return call_TraceReturn();
}

// TraceSQLAllocConnect
int __stdcall _TraceSQLAllocConnect() {
	return call_TraceSQLAllocConnect();
}

// TraceSQLAllocEnv
int __stdcall _TraceSQLAllocEnv() {
	return call_TraceSQLAllocEnv();
}

// TraceSQLAllocHandle
int __stdcall _TraceSQLAllocHandle() {
	return call_TraceSQLAllocHandle();
}

// TraceSQLAllocHandleStd
int __stdcall _TraceSQLAllocHandleStd() {
	return call_TraceSQLAllocHandleStd();
}

// TraceSQLAllocHandleStdW
int __stdcall _TraceSQLAllocHandleStdW() {
	return call_TraceSQLAllocHandleStdW();
}

// TraceSQLAllocStmt
int __stdcall _TraceSQLAllocStmt() {
	return call_TraceSQLAllocStmt();
}

// TraceSQLBindCol
int __stdcall _TraceSQLBindCol() {
	return call_TraceSQLBindCol();
}

// TraceSQLBindParam
int __stdcall _TraceSQLBindParam() {
	return call_TraceSQLBindParam();
}

// TraceSQLBindParameter
int __stdcall _TraceSQLBindParameter() {
	return call_TraceSQLBindParameter();
}

// TraceSQLBrowseConnect
int __stdcall _TraceSQLBrowseConnect() {
	return call_TraceSQLBrowseConnect();
}

// TraceSQLBrowseConnectW
int __stdcall _TraceSQLBrowseConnectW() {
	return call_TraceSQLBrowseConnectW();
}

// TraceSQLBulkOperations
int __stdcall _TraceSQLBulkOperations() {
	return call_TraceSQLBulkOperations();
}

// TraceSQLCancel
int __stdcall _TraceSQLCancel() {
	return call_TraceSQLCancel();
}

// TraceSQLCancelHandle
int __stdcall _TraceSQLCancelHandle() {
	return call_TraceSQLCancelHandle();
}

// TraceSQLCloseCursor
int __stdcall _TraceSQLCloseCursor() {
	return call_TraceSQLCloseCursor();
}

// TraceSQLColAttribute
int __stdcall _TraceSQLColAttribute() {
	return call_TraceSQLColAttribute();
}

// TraceSQLColAttributes
int __stdcall _TraceSQLColAttributes() {
	return call_TraceSQLColAttributes();
}

// TraceSQLColAttributesW
int __stdcall _TraceSQLColAttributesW() {
	return call_TraceSQLColAttributesW();
}

// TraceSQLColAttributeW
int __stdcall _TraceSQLColAttributeW() {
	return call_TraceSQLColAttributeW();
}

// TraceSQLColumnPrivileges
int __stdcall _TraceSQLColumnPrivileges() {
	return call_TraceSQLColumnPrivileges();
}

// TraceSQLColumnPrivilegesW
int __stdcall _TraceSQLColumnPrivilegesW() {
	return call_TraceSQLColumnPrivilegesW();
}

// TraceSQLColumns
int __stdcall _TraceSQLColumns() {
	return call_TraceSQLColumns();
}

// TraceSQLColumnsW
int __stdcall _TraceSQLColumnsW() {
	return call_TraceSQLColumnsW();
}

// TraceSQLConnect
int __stdcall _TraceSQLConnect() {
	return call_TraceSQLConnect();
}

// TraceSQLConnectW
int __stdcall _TraceSQLConnectW() {
	return call_TraceSQLConnectW();
}

// TraceSQLCopyDesc
int __stdcall _TraceSQLCopyDesc() {
	return call_TraceSQLCopyDesc();
}

// TraceSQLDataSources
int __stdcall _TraceSQLDataSources() {
	return call_TraceSQLDataSources();
}

// TraceSQLDataSourcesW
int __stdcall _TraceSQLDataSourcesW() {
	return call_TraceSQLDataSourcesW();
}

// TraceSQLDescribeCol
int __stdcall _TraceSQLDescribeCol() {
	return call_TraceSQLDescribeCol();
}

// TraceSQLDescribeColW
int __stdcall _TraceSQLDescribeColW() {
	return call_TraceSQLDescribeColW();
}

// TraceSQLDescribeParam
int __stdcall _TraceSQLDescribeParam() {
	return call_TraceSQLDescribeParam();
}

// TraceSQLDisconnect
int __stdcall _TraceSQLDisconnect() {
	return call_TraceSQLDisconnect();
}

// TraceSQLDriverConnect
int __stdcall _TraceSQLDriverConnect() {
	return call_TraceSQLDriverConnect();
}

// TraceSQLDriverConnectW
int __stdcall _TraceSQLDriverConnectW() {
	return call_TraceSQLDriverConnectW();
}

// TraceSQLDrivers
int __stdcall _TraceSQLDrivers() {
	return call_TraceSQLDrivers();
}

// TraceSQLDriversW
int __stdcall _TraceSQLDriversW() {
	return call_TraceSQLDriversW();
}

// TraceSQLEndTran
int __stdcall _TraceSQLEndTran() {
	return call_TraceSQLEndTran();
}

// TraceSQLError
int __stdcall _TraceSQLError() {
	return call_TraceSQLError();
}

// TraceSQLErrorW
int __stdcall _TraceSQLErrorW() {
	return call_TraceSQLErrorW();
}

// TraceSQLExecDirect
int __stdcall _TraceSQLExecDirect() {
	return call_TraceSQLExecDirect();
}

// TraceSQLExecDirectW
int __stdcall _TraceSQLExecDirectW() {
	return call_TraceSQLExecDirectW();
}

// TraceSQLExecute
int __stdcall _TraceSQLExecute() {
	return call_TraceSQLExecute();
}

// TraceSQLExtendedFetch
int __stdcall _TraceSQLExtendedFetch() {
	return call_TraceSQLExtendedFetch();
}

// TraceSQLFetch
int __stdcall _TraceSQLFetch() {
	return call_TraceSQLFetch();
}

// TraceSQLFetchScroll
int __stdcall _TraceSQLFetchScroll() {
	return call_TraceSQLFetchScroll();
}

// TraceSQLForeignKeys
int __stdcall _TraceSQLForeignKeys() {
	return call_TraceSQLForeignKeys();
}

// TraceSQLForeignKeysW
int __stdcall _TraceSQLForeignKeysW() {
	return call_TraceSQLForeignKeysW();
}

// TraceSQLFreeConnect
int __stdcall _TraceSQLFreeConnect() {
	return call_TraceSQLFreeConnect();
}

// TraceSQLFreeEnv
int __stdcall _TraceSQLFreeEnv() {
	return call_TraceSQLFreeEnv();
}

// TraceSQLFreeHandle
int __stdcall _TraceSQLFreeHandle() {
	return call_TraceSQLFreeHandle();
}

// TraceSQLFreeStmt
int __stdcall _TraceSQLFreeStmt() {
	return call_TraceSQLFreeStmt();
}

// TraceSQLGetConnectAttr
int __stdcall _TraceSQLGetConnectAttr() {
	return call_TraceSQLGetConnectAttr();
}

// TraceSQLGetConnectAttrW
int __stdcall _TraceSQLGetConnectAttrW() {
	return call_TraceSQLGetConnectAttrW();
}

// TraceSQLGetConnectOption
int __stdcall _TraceSQLGetConnectOption() {
	return call_TraceSQLGetConnectOption();
}

// TraceSQLGetConnectOptionW
int __stdcall _TraceSQLGetConnectOptionW() {
	return call_TraceSQLGetConnectOptionW();
}

// TraceSQLGetCursorName
int __stdcall _TraceSQLGetCursorName() {
	return call_TraceSQLGetCursorName();
}

// TraceSQLGetCursorNameW
int __stdcall _TraceSQLGetCursorNameW() {
	return call_TraceSQLGetCursorNameW();
}

// TraceSQLGetData
int __stdcall _TraceSQLGetData() {
	return call_TraceSQLGetData();
}

// TraceSQLGetDescField
int __stdcall _TraceSQLGetDescField() {
	return call_TraceSQLGetDescField();
}

// TraceSQLGetDescFieldW
int __stdcall _TraceSQLGetDescFieldW() {
	return call_TraceSQLGetDescFieldW();
}

// TraceSQLGetDescRec
int __stdcall _TraceSQLGetDescRec() {
	return call_TraceSQLGetDescRec();
}

// TraceSQLGetDescRecW
int __stdcall _TraceSQLGetDescRecW() {
	return call_TraceSQLGetDescRecW();
}

// TraceSQLGetDiagField
int __stdcall _TraceSQLGetDiagField() {
	return call_TraceSQLGetDiagField();
}

// TraceSQLGetDiagFieldW
int __stdcall _TraceSQLGetDiagFieldW() {
	return call_TraceSQLGetDiagFieldW();
}

// TraceSQLGetDiagRec
int __stdcall _TraceSQLGetDiagRec() {
	return call_TraceSQLGetDiagRec();
}

// TraceSQLGetDiagRecW
int __stdcall _TraceSQLGetDiagRecW() {
	return call_TraceSQLGetDiagRecW();
}

// TraceSQLGetEnvAttr
int __stdcall _TraceSQLGetEnvAttr() {
	return call_TraceSQLGetEnvAttr();
}

// TraceSQLGetFunctions
int __stdcall _TraceSQLGetFunctions() {
	return call_TraceSQLGetFunctions();
}

// TraceSQLGetInfo
int __stdcall _TraceSQLGetInfo() {
	return call_TraceSQLGetInfo();
}

// TraceSQLGetInfoW
int __stdcall _TraceSQLGetInfoW() {
	return call_TraceSQLGetInfoW();
}

// TraceSQLGetStmtAttr
int __stdcall _TraceSQLGetStmtAttr() {
	return call_TraceSQLGetStmtAttr();
}

// TraceSQLGetStmtAttrW
int __stdcall _TraceSQLGetStmtAttrW() {
	return call_TraceSQLGetStmtAttrW();
}

// TraceSQLGetStmtOption
int __stdcall _TraceSQLGetStmtOption() {
	return call_TraceSQLGetStmtOption();
}

// TraceSQLGetTypeInfo
int __stdcall _TraceSQLGetTypeInfo() {
	return call_TraceSQLGetTypeInfo();
}

// TraceSQLGetTypeInfoW
int __stdcall _TraceSQLGetTypeInfoW() {
	return call_TraceSQLGetTypeInfoW();
}

// TraceSQLMoreResults
int __stdcall _TraceSQLMoreResults() {
	return call_TraceSQLMoreResults();
}

// TraceSQLNativeSql
int __stdcall _TraceSQLNativeSql() {
	return call_TraceSQLNativeSql();
}

// TraceSQLNativeSqlW
int __stdcall _TraceSQLNativeSqlW() {
	return call_TraceSQLNativeSqlW();
}

// TraceSQLNumParams
int __stdcall _TraceSQLNumParams() {
	return call_TraceSQLNumParams();
}

// TraceSQLNumResultCols
int __stdcall _TraceSQLNumResultCols() {
	return call_TraceSQLNumResultCols();
}

// TraceSQLParamData
int __stdcall _TraceSQLParamData() {
	return call_TraceSQLParamData();
}

// TraceSQLParamOptions
int __stdcall _TraceSQLParamOptions() {
	return call_TraceSQLParamOptions();
}

// TraceSQLPrepare
int __stdcall _TraceSQLPrepare() {
	return call_TraceSQLPrepare();
}

// TraceSQLPrepareW
int __stdcall _TraceSQLPrepareW() {
	return call_TraceSQLPrepareW();
}

// TraceSQLPrimaryKeys
int __stdcall _TraceSQLPrimaryKeys() {
	return call_TraceSQLPrimaryKeys();
}

// TraceSQLPrimaryKeysW
int __stdcall _TraceSQLPrimaryKeysW() {
	return call_TraceSQLPrimaryKeysW();
}

// TraceSQLProcedureColumns
int __stdcall _TraceSQLProcedureColumns() {
	return call_TraceSQLProcedureColumns();
}

// TraceSQLProcedureColumnsW
int __stdcall _TraceSQLProcedureColumnsW() {
	return call_TraceSQLProcedureColumnsW();
}

// TraceSQLProcedures
int __stdcall _TraceSQLProcedures() {
	return call_TraceSQLProcedures();
}

// TraceSQLProceduresW
int __stdcall _TraceSQLProceduresW() {
	return call_TraceSQLProceduresW();
}

// TraceSQLPutData
int __stdcall _TraceSQLPutData() {
	return call_TraceSQLPutData();
}

// TraceSQLRowCount
int __stdcall _TraceSQLRowCount() {
	return call_TraceSQLRowCount();
}

// TraceSQLSetConnectAttr
int __stdcall _TraceSQLSetConnectAttr() {
	return call_TraceSQLSetConnectAttr();
}

// TraceSQLSetConnectAttrW
int __stdcall _TraceSQLSetConnectAttrW() {
	return call_TraceSQLSetConnectAttrW();
}

// TraceSQLSetConnectOption
int __stdcall _TraceSQLSetConnectOption() {
	return call_TraceSQLSetConnectOption();
}

// TraceSQLSetConnectOptionW
int __stdcall _TraceSQLSetConnectOptionW() {
	return call_TraceSQLSetConnectOptionW();
}

// TraceSQLSetCursorName
int __stdcall _TraceSQLSetCursorName() {
	return call_TraceSQLSetCursorName();
}

// TraceSQLSetCursorNameW
int __stdcall _TraceSQLSetCursorNameW() {
	return call_TraceSQLSetCursorNameW();
}

// TraceSQLSetDescField
int __stdcall _TraceSQLSetDescField() {
	return call_TraceSQLSetDescField();
}

// TraceSQLSetDescFieldW
int __stdcall _TraceSQLSetDescFieldW() {
	return call_TraceSQLSetDescFieldW();
}

// TraceSQLSetDescRec
int __stdcall _TraceSQLSetDescRec() {
	return call_TraceSQLSetDescRec();
}

// TraceSQLSetEnvAttr
int __stdcall _TraceSQLSetEnvAttr() {
	return call_TraceSQLSetEnvAttr();
}

// TraceSQLSetParam
int __stdcall _TraceSQLSetParam() {
	return call_TraceSQLSetParam();
}

// TraceSQLSetPos
int __stdcall _TraceSQLSetPos() {
	return call_TraceSQLSetPos();
}

// TraceSQLSetScrollOptions
int __stdcall _TraceSQLSetScrollOptions() {
	return call_TraceSQLSetScrollOptions();
}

// TraceSQLSetStmtAttr
int __stdcall _TraceSQLSetStmtAttr() {
	return call_TraceSQLSetStmtAttr();
}

// TraceSQLSetStmtAttrW
int __stdcall _TraceSQLSetStmtAttrW() {
	return call_TraceSQLSetStmtAttrW();
}

// TraceSQLSetStmtOption
int __stdcall _TraceSQLSetStmtOption() {
	return call_TraceSQLSetStmtOption();
}

// TraceSQLSpecialColumns
int __stdcall _TraceSQLSpecialColumns() {
	return call_TraceSQLSpecialColumns();
}

// TraceSQLSpecialColumnsW
int __stdcall _TraceSQLSpecialColumnsW() {
	return call_TraceSQLSpecialColumnsW();
}

// TraceSQLStatistics
int __stdcall _TraceSQLStatistics() {
	return call_TraceSQLStatistics();
}

// TraceSQLStatisticsW
int __stdcall _TraceSQLStatisticsW() {
	return call_TraceSQLStatisticsW();
}

// TraceSQLTablePrivileges
int __stdcall _TraceSQLTablePrivileges() {
	return call_TraceSQLTablePrivileges();
}

// TraceSQLTablePrivilegesW
int __stdcall _TraceSQLTablePrivilegesW() {
	return call_TraceSQLTablePrivilegesW();
}

// TraceSQLTables
int __stdcall _TraceSQLTables() {
	return call_TraceSQLTables();
}

// TraceSQLTablesW
int __stdcall _TraceSQLTablesW() {
	return call_TraceSQLTablesW();
}

// TraceSQLTransact
int __stdcall _TraceSQLTransact() {
	return call_TraceSQLTransact();
}

// TraceVersion
int __stdcall _TraceVersion() {
	return call_TraceVersion();
}

// TraceVSControl
int __stdcall _TraceVSControl() {
	return call_TraceVSControl();
}


from typing import Any, Dict, List

OWASP_ASVS_CHECKLIST = [
    {"id": "V1", "name": "Secure Software Development Lifecycle", "category": "Architecture"},
    {"id": "V2", "name": "Authentication", "category": "Authentication"},
    {"id": "V3", "name": "Session Management", "category": "Session"},
    {"id": "V4", "name": "Access Control", "category": "Access Control"},
    {"id": "V5", "name": "Validation, Sanitization and Encoding", "category": "Validation"},
    {"id": "V6", "name": "Stored Cryptography", "category": "Cryptography"},
    {"id": "V7", "name": "Error Handling and Logging", "category": "Resilience"},
    {"id": "V8", "name": "Data Protection", "category": "Data Protection"},
    {"id": "V9", "name": "Communication", "category": "Communication"},
    {"id": "V10", "name": "Malicious Code", "category": "Malicious Code"},
    {"id": "V11", "name": "Business Logic", "category": "Business Logic"},
    {"id": "V12", "name": "Files and Resources", "category": "Files"},
    {"id": "V13", "name": "API and Web Services", "category": "API"},
    {"id": "V14", "name": "Configuration", "category": "Configuration"},
]

CIS_CHECKLIST = [
    {"id": "CIS-1", "name": "Inventory and Control of Enterprise Assets", "category": "Inventory"},
    {"id": "CIS-2", "name": "Inventory and Control of Software Assets", "category": "Software"},
    {"id": "CIS-3", "name": "Data Protection", "category": "Data"},
    {"id": "CIS-4", "name": "Secure Configuration", "category": "Configuration"},
    {"id": "CIS-5", "name": "Account Management", "category": "Identity"},
    {"id": "CIS-6", "name": "Access Control", "category": "Access"},
    {"id": "CIS-7", "name": "Continuous Vulnerability Management", "category": "Vuln Mgmt"},
    {"id": "CIS-8", "name": "Audit Log Management", "category": "Logging"},
]

def get_owasp_asvs() -> List[Dict[str, Any]]:
    return OWASP_ASVS_CHECKLIST.copy()

def get_cis() -> List[Dict[str, Any]]:
    return CIS_CHECKLIST.copy()

def compliance_list(framework: str) -> List[Dict[str, Any]]:
    if framework.lower() == "owasp" or framework.lower() == "asvs":
        return get_owasp_asvs()
    if framework.lower() == "cis":
        return get_cis()
    return []

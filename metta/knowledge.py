from hyperon import MeTTa, E, S, ValueAtom

def initialize_knowledge_graph(metta: MeTTa):
    """Initialize the MeTTa knowledge graph with MITRE ATT&CK, incidents, and response actions."""
    
    # Indicators → Techniques (MITRE ATT&CK)
    metta.space().add_atom(E(S("indicator"), S("powershell"), S("T1059.001")))
    metta.space().add_atom(E(S("indicator"), S("scheduled_task"), S("T1053.005")))
    metta.space().add_atom(E(S("indicator"), S("smb_traffic"), S("T1021.002")))
    metta.space().add_atom(E(S("indicator"), S("rdp_connection"), S("T1021.001")))
    metta.space().add_atom(E(S("indicator"), S("lsass_access"), S("T1003.001")))
    metta.space().add_atom(E(S("indicator"), S("file_encryption"), S("T1486")))
    metta.space().add_atom(E(S("indicator"), S("obfuscated_code"), S("T1027")))
    metta.space().add_atom(E(S("indicator"), S("registry_modification"), S("T1112")))
    metta.space().add_atom(E(S("indicator"), S("wmi_execution"), S("T1047")))
    
    # Techniques → Tactics (MITRE ATT&CK)
    metta.space().add_atom(E(S("technique"), S("T1059.001"), S("TA0002")))  
    metta.space().add_atom(E(S("technique"), S("T1053.005"), S("TA0003"))) 
    metta.space().add_atom(E(S("technique"), S("T1021.002"), S("TA0008")))  
    metta.space().add_atom(E(S("technique"), S("T1021.001"), S("TA0008")))  
    metta.space().add_atom(E(S("technique"), S("T1003.001"), S("TA0006")))  
    metta.space().add_atom(E(S("technique"), S("T1486"), S("TA0040")))      
    metta.space().add_atom(E(S("technique"), S("T1027"), S("TA0005")))      
    metta.space().add_atom(E(S("technique"), S("T1112"), S("TA0005")))      
    metta.space().add_atom(E(S("technique"), S("T1047"), S("TA0002")))      
    
    # Tactics → Attack Phases
    metta.space().add_atom(E(S("tactic"), S("TA0002"), ValueAtom("execution_phase")))
    metta.space().add_atom(E(S("tactic"), S("TA0003"), ValueAtom("persistence_phase")))
    metta.space().add_atom(E(S("tactic"), S("TA0006"), ValueAtom("credential_access_phase")))
    metta.space().add_atom(E(S("tactic"), S("TA0008"), ValueAtom("lateral_movement_phase")))
    metta.space().add_atom(E(S("tactic"), S("TA0040"), ValueAtom("impact_phase")))
    metta.space().add_atom(E(S("tactic"), S("TA0005"), ValueAtom("defense_evasion_phase")))
    
    # Techniques → Severity
    metta.space().add_atom(E(S("severity"), S("T1486"), ValueAtom("critical")))       # Ransomware
    metta.space().add_atom(E(S("severity"), S("T1003.001"), ValueAtom("high")))       # Credential Dumping
    metta.space().add_atom(E(S("severity"), S("T1021.002"), ValueAtom("high")))       # SMB Lateral Movement
    metta.space().add_atom(E(S("severity"), S("T1021.001"), ValueAtom("high")))       # RDP
    metta.space().add_atom(E(S("severity"), S("T1053.005"), ValueAtom("medium")))     # Scheduled Task
    metta.space().add_atom(E(S("severity"), S("T1059.001"), ValueAtom("medium")))     # PowerShell
    metta.space().add_atom(E(S("severity"), S("T1027"), ValueAtom("medium")))         # Obfuscation
    
    # Attack Patterns → Response Actions
    metta.space().add_atom(E(S("response"), S("lateral_movement"), ValueAtom("Isolate affected systems, block SMB/RDP, reset credentials")))
    metta.space().add_atom(E(S("response"), S("ransomware"), ValueAtom("Isolate systems, protect backups, identify variant, stop encryption")))
    metta.space().add_atom(E(S("response"), S("credential_access"), ValueAtom("Reset all passwords, review access logs, enable MFA")))
    metta.space().add_atom(E(S("response"), S("persistence"), ValueAtom("Remove scheduled tasks, check startup items, scan for backdoors")))
    metta.space().add_atom(E(S("response"), S("execution"), ValueAtom("Monitor process execution, review PowerShell logs, deploy EDR")))
    
    # Asset Types → Base Severity
    metta.space().add_atom(E(S("asset_severity"), S("domain_controller"), ValueAtom("critical")))
    metta.space().add_atom(E(S("asset_severity"), S("file_server"), ValueAtom("high")))
    metta.space().add_atom(E(S("asset_severity"), S("database"), ValueAtom("high")))
    metta.space().add_atom(E(S("asset_severity"), S("workstation"), ValueAtom("medium")))
    metta.space().add_atom(E(S("asset_severity"), S("web_server"), ValueAtom("high")))
    
    # FAQs
    metta.space().add_atom(E(S("faq"), S("What should I do first?"), ValueAtom("Contain the threat immediately - isolate affected systems and prevent lateral movement.")))
    metta.space().add_atom(E(S("faq"), S("How do I stop the attack?"), ValueAtom("Follow the prioritized actions: isolate, block, reset credentials, and collect evidence.")))
    metta.space().add_atom(E(S("faq"), S("Is this ransomware?"), ValueAtom("Check for file encryption activity. If present, protect backups immediately and isolate systems.")))
    metta.space().add_atom(E(S("faq"), S("Should I reset passwords?"), ValueAtom("Yes, if credential access is suspected. Reset all administrative passwords and enable MFA.")))

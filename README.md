# Incident-Response-MeTTa-Agent
🛡️ Cybersecurity Incident Response MeTTa Agent
An autonomous AI agent that leverages the MeTTa knowledge graph and Large Language Models for dynamic cybersecurity incident response. This agent is designed to understand natural language incident reports, reason over a symbolic knowledge base, and provide actionable, prioritized response guidance.

🎯 Overview
In the fast-paced world of cybersecurity, rapid and accurate incident analysis is critical. This agent streamlines the initial response process by:

Perceiving incident descriptions provided in plain English.

Reasoning through a MeTTa-based knowledge graph populated with MITRE ATT&CK® data.

Acting by delivering clear, prioritized response actions to security analysts.

This approach combines the strengths of symbolic AI for logical rigor with the flexibility of Large Language Models for natural language interaction.

✨ Features
✅ MITRE ATT&CK® Knowledge Graph: Pre-loaded with techniques, tactics, and attack phases for robust analysis.

✅ MeTTa Logical Reasoning: Employs symbolic AI to infer relationships, severity, and appropriate responses.

✅ ASI:One LLM Integration: Utilizes the powerful asi1-mini model for natural language understanding and generation.

✅ Dynamic Learning: Automatically enriches its knowledge graph when encountering novel indicators, learning from every interaction.

✅ Session Tracking: Maintains context through multi-turn conversations for comprehensive incident analysis.

✅ Automated Severity Calculation: Determines incident severity (Critical, High, Medium, Low) based on logical rules.

✅ Actionable Guidance: Provides prioritized, context-aware incident response recommendations.

🏗️ Architecture & Flow
The agent follows a simple yet powerful data processing pipeline:

User Query
     ↓
MeTTa RAG (MITRE ATT&CK Knowledge Graph)
     ↓
ASI:One LLM (asi1-mini for NLU & NLG)
     ↓
Incident Response Guidance

    How It Works

User Query: An analyst describes an observation, such as "SMB traffic between DC01 and file servers with scheduled tasks being created".

Intent Classification: The ASI:One LLM analyzes the query to extract key cybersecurity indicators (e.g., smb_traffic, scheduled_task).

MeTTa RAG Query: The agent queries its symbolic knowledge graph to find matching MITRE ATT&CK® techniques and tactics associated with the indicators.

Logical Reasoning: MeTTa applies logical rules to determine the attack phase, calculate a severity score, and identify relevant mitigation steps.

Response Generation: The ASI:One LLM synthesizes the structured output from MeTTa into a professional, human-readable response.

Deliver Guidance: The final analysis and recommended actions are sent back to the user.

🚀 Getting Started
Follow these steps to get your agent up and running.

Prerequisites
Python 3.9+

An active ASI:One API Key

1. Clone the Repository
Bash

git clone <your-repository-url>
cd agent_clean
2. Install Dependencies
Bash

pip install -r requirements.txt
3. Configure Your Environment
Copy the example environment file and add your API key.

Bash

# Copy the example .env file
cp .env.example .env
Now, edit the .env file and set your ASI_ONE_API_KEY:

Code snippet

ASI_ONE_API_KEY=your-asi-one-api-key
4. Run the Agent
Bash

python agent.py
💬 Example Usage
Interact with the agent using natural language queries.

Query 1: Suspicious PowerShell Activity
User: "I'm seeing PowerShell execution on DC01"

Agent Response:

MITRE Technique: T1059.001 (Command and Scripting Interpreter: PowerShell)

Tactic: Execution (TA0002)

Severity: Medium

Recommended Actions:

Enable and monitor PowerShell command-line logging.

Review logs for anomalous commands or scripts.

Deploy EDR solutions to detect and block malicious PowerShell usage.

Query 2: Potential Lateral Movement
User: "SMB traffic between DC01 and file servers with scheduled tasks being created"

Agent Response:

MITRE Techniques: T1021.002 (Remote Services: SMB/Windows Admin Shares), T1053.005 (Scheduled Task/Job: Scheduled Task)

Tactics: Lateral Movement (TA0008) & Persistence (TA0003)

Severity: High

Recommended Actions:

Isolate the affected systems from the network.

Block unnecessary SMB/RDP traffic between servers.

Reset credentials for all involved accounts.

Query 3: Active Ransomware Attack
User: "Files are being encrypted across multiple servers"

Agent Response:

MITRE Technique: T1486 (Data Encrypted for Impact)

Tactic: Impact (TA0040)

Severity: Critical

Recommended Actions:

Immediately isolate all affected systems to prevent further spread.

Secure and protect backups by taking them offline.

Begin forensic analysis to identify the ransomware variant and initial access vector.

🧠 The MeTTa Knowledge Graph
The core of the agent's reasoning capability lies in its MeTTa knowledge graph.

Knowledge Relations
The graph is built on a set of logical relationships:

Indicators → Techniques: (powershell → T1059.001)

Techniques → Tactics: (T1059.001 → TA0002)

Tactics → Attack Phases: (TA0002 → execution_phase)

Techniques → Severity: (T1486 → critical)

Dynamic Learning
The agent is not static. When it encounters an unknown indicator, it uses the ASI:One LLM to hypothesize a corresponding MITRE ATT&CK® technique. This new association is then added to the knowledge graph, allowing the agent to grow smarter and more effective with each interaction.
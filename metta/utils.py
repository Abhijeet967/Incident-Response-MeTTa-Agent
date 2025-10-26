import json
from openai import OpenAI
from .incidentrag import IncidentRAG

class LLM:
    def __init__(self, api_key):
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.asi1.ai/v1"
        )

    def create_completion(self, prompt, max_tokens=300):
        completion = self.client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="asi1-mini",  # ASI:One model name
            max_tokens=max_tokens
        )
        return completion.choices[0].message.content

def get_intent_and_indicators(query, llm):
    """Use LLM to classify intent and extract indicators."""
    prompt = (
        f"Given the cybersecurity query: '{query}'\n"
        "Classify the intent as one of: 'indicator', 'response', 'faq', or 'unknown'.\n"
        "Extract the most relevant cybersecurity indicators (e.g., powershell, smb_traffic, file_encryption, scheduled_task, rdp_connection, lsass_access).\n"
        "Return *only* the result in JSON format like this, with no additional text:\n"
        "{\n"
        "  \"intent\": \"<classified_intent>\",\n"
        "  \"indicators\": [\"<indicator1>\", \"<indicator2>\"]\n"
        "}"
    )
    response = llm.create_completion(prompt)
    try:
        result = json.loads(response)
        return result["intent"], result.get("indicators", [])
    except json.JSONDecodeError:
        print(f"Error parsing LLM response: {response}")
        return "unknown", []

def generate_knowledge_response(query, intent, indicators, llm):
    """Use LLM to generate a response for new knowledge based on intent."""
    if intent == "indicator" and indicators:
        prompt = (
            f"Query: '{query}'\n"
            f"The indicators '{', '.join(indicators)}' are not fully mapped in my knowledge base.\n"
            "Suggest MITRE ATT&CK techniques that might be associated with these indicators.\n"
            "Return *only* the technique IDs (e.g., T1059.001, T1021.002), comma-separated, no additional text."
        )
    elif intent == "response":
        prompt = (
            f"Query: '{query}'\n"
            "Suggest prioritized incident response actions for this situation.\n"
            "Return *only* the actions as a concise, comma-separated list, no additional text."
        )
    elif intent == "faq":
        prompt = (
            f"Query: '{query}'\n"
            "This is a new cybersecurity FAQ. Provide a concise, helpful answer.\n"
            "Return *only* the answer, no additional text."
        )
    else:
        return None
    return llm.create_completion(prompt)

def process_query(query, rag: IncidentRAG, llm: LLM):
    """Process incident query using RAG and LLM (matching medical agent pattern)."""
    intent, indicators = get_intent_and_indicators(query, llm)
    print(f"Intent: {intent}, Indicators: {indicators}")
    prompt = ""

    if intent == "faq":
        faq_answer = rag.query_faq(query)
        if not faq_answer:
            new_answer = generate_knowledge_response(query, intent, indicators, llm)
            if new_answer:
                rag.add_knowledge("faq", query, new_answer)
                print(f"Knowledge graph updated - Added FAQ: '{query}' → '{new_answer}'")
            prompt = (
                f"Query: '{query}'\n"
                f"FAQ Answer: '{new_answer or 'General assistance'}'\n"
                "Humanize this for a security analyst with a professional tone."
            )
        else:
            prompt = (
                f"Query: '{query}'\n"
                f"FAQ Answer: '{faq_answer}'\n"
                "Humanize this for a security analyst with a professional tone."
            )
    
    elif intent == "indicator" and indicators:
        all_techniques = []
        all_tactics = []
        all_phases = []
        all_severities = []
        
        for indicator in indicators:
            techniques = rag.query_indicator(indicator)
            if not techniques:
                # Generate new knowledge
                new_technique = generate_knowledge_response(query, intent, [indicator], llm)
                if new_technique:
                    rag.add_knowledge("indicator", indicator, new_technique)
                    print(f"Knowledge graph updated - Added indicator: '{indicator}' → '{new_technique}'")
                    techniques = [new_technique]
            
            all_techniques.extend(techniques)
            
            for technique in techniques:
                tactics = rag.get_tactic(technique)
                all_tactics.extend(tactics)
                
                severities = rag.get_severity(technique)
                all_severities.extend(severities)
                
                for tactic in tactics:
                    phases = rag.get_attack_phase(tactic)
                    all_phases.extend(phases)
        
        # Determine highest severity
        severity_order = ["critical", "high", "medium", "low"]
        final_severity = "unknown"
        for sev in severity_order:
            if sev in all_severities:
                final_severity = sev
                break
        
        # Get response actions based on phase
        attack_pattern = all_phases[0] if all_phases else "execution"
        attack_pattern = attack_pattern.replace("_phase", "")
        response_actions = rag.get_response_actions(attack_pattern)
        
        prompt = (
            f"Query: '{query}'\n"
            f"Indicators Detected: {', '.join(indicators)}\n"
            f"MITRE Techniques: {', '.join(list(set(all_techniques)))}\n"
            f"Attack Phase: {', '.join(list(set(all_phases)))}\n"
            f"Severity: {final_severity}\n"
            f"Response Actions: {', '.join(response_actions) if response_actions else 'Assess and contain'}\n"
            "Generate a professional, actionable incident response for a security analyst."
        )
    
    elif intent == "response":
        response_actions = generate_knowledge_response(query, intent, indicators, llm)
        prompt = (
            f"Query: '{query}'\n"
            f"Response Actions: {response_actions}\n"
            "Provide clear, actionable incident response guidance."
        )
    
    if not prompt:
        prompt = f"Query: '{query}'\nNo specific match found. Provide general cybersecurity incident response guidance."

    prompt += "\nFormat response as: 'Selected Question: <question>' on first line, 'Humanized Answer: <response>' on second."
    response = llm.create_completion(prompt, max_tokens=400)
    
    try:
        lines = response.split('\n')
        selected_q = lines[0].replace("Selected Question: ", "").strip()
        answer = '\n'.join(lines[1:]).replace("Humanized Answer: ", "").strip()
        return {"selected_question": selected_q, "humanized_answer": answer}
    except IndexError:
        return {"selected_question": query, "humanized_answer": response}

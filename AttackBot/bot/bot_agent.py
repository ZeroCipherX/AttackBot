import re
import requests
import json
from . import data_utils
from .vector_utils import search_cve  # <== Add this!

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3"  # or llama3, mistral, etc.


# --- Patterns to extract entities ---
def extract_entities(question):
   cve_pattern = r"CVE-\d{4}-\d{4,7}"
   ttp_pattern = r"T\d{4,5}(?:\.\d{3})?"
   apt_pattern = r"APT[ -]?[A-Za-z0-9]+"

   cve_ids = re.findall(cve_pattern, question, re.IGNORECASE)
   ttp_ids = re.findall(ttp_pattern, question, re.IGNORECASE)
   apt_ids = re.findall(apt_pattern, question, re.IGNORECASE)

   return cve_ids, ttp_ids, apt_ids


# --- Main dataset query ---
def query_dataset(question):
   cve_ids, ttp_ids, apt_ids = extract_entities(question)
   results = []

   # --- if explicit CVE(s) found ---
   for cve_id in cve_ids:
       details = data_utils.get_cve_details(cve_id)
       if details:
           results.append(f"## 🛡️ CVE {cve_id}\n{details}")
       ttps = data_utils.get_ttps_for_cve(cve_id)
       if ttps:
           results.append(f"### 📋 TTPs\n{', '.join(ttps)}")
       exploits = data_utils.get_exploits_mapped(cve_id)
       if exploits:
           results.append(f"### 🚀 Exploits (Mapped)\n{', '.join(exploits)}")
       kev = data_utils.get_kev_details(cve_id)
       if kev:
           results.append(f"### 🔍 Known Exploited Vulnerabilities (KEV)\n{kev}")
       cvss = data_utils.get_cvss_details(cve_id)
       if cvss:
           results.append(f"### 📝 CVSS Score & Severity\n{cvss}")
       attack_mapping = data_utils.get_attack_mapping(cve_id)
       if attack_mapping:
           results.append(f"### 🎯 ATT&CK Mapping\n{attack_mapping}")
       for ttp in ttps:
           apts = data_utils.get_apts_for_ttp(ttp)
           if apts:
               results.append(f"### 👥 APTs for {ttp}\n{', '.join(apts)}")

   # --- if explicit TTP(s) found ---
   for ttp_id in ttp_ids:
       details = data_utils.get_ttp_details(ttp_id)
       if details:
           results.append(f"## 📋 TTP {ttp_id}\n{details}")
       apts = data_utils.get_apts_for_ttp(ttp_id)
       if apts:
           results.append(f"### 👥 APTs\n{', '.join(apts)}")

   # --- if explicit APT(s) found ---
   for apt_id in apt_ids:
       details = data_utils.get_apt_details(apt_id)
       if details:
           results.append(f"## 🎯 APT {apt_id}\n{details}")

   # --- fallback: keyword search ---
   if not (cve_ids or ttp_ids or apt_ids):
       keyword = question.lower()
       matches = data_utils.search_cves_by_keyword(keyword)
       if matches:
           results.append("### 🔎 CVEs related to your query:")
           for cve_id, desc in matches:
               results.append(f"- 🛡️ {cve_id}: {desc}")

   return "\n\n".join(results)


# --- Call Ollama directly ---
def call_ollama(question):
   system_prompt = (
       "You are a professional cybersecurity assistant. "
       "You help users by answering their questions about CVEs (Common Vulnerabilities and Exposures), "
       "TTPs (MITRE Techniques), APT groups, and related predictions. "
       "If there is no exact data available, you provide plausible, contextually correct, "
       "cybersecurity-focused information. If the question is a greeting or casual talk, "
       "respond politely and in a friendly tone. "
       "Never mention irrelevant topics. "
       "If truly no relevant answer exists, reply: 'No verified cybersecurity information found.'"
   )

   payload = {
       "model": OLLAMA_MODEL,
       "prompt": f"{system_prompt}\n\nUser: {question}\n\nAssistant:",
       "stream": False
   }

   headers = {"Content-Type": "application/json"}

   try:
       resp = requests.post(OLLAMA_URL, headers=headers, data=json.dumps(payload), timeout=60)
       resp.raise_for_status()
       data = resp.json()
       return data.get("response", "").strip()
   except Exception as e:
       return f"⚠️ Error contacting LLM: {e}"


# --- Main entry point ---
def answer_question(question):
   # 1️⃣ Try exact matches first
   dataset_answer = query_dataset(question)
   if dataset_answer.strip():
       return dataset_answer

   # 2️⃣ Try vector semantic search
   try:
       vector_results = search_cve(question)
       if vector_results:
           response = "### 🔎 Most relevant CVEs:\n"
           for cve_id, desc in vector_results:
               response += f"- 🛡️ {cve_id}: {desc}\n"
           return response
   except Exception as e:
       print(f"⚠️ Vector search error: {e}")

   # 3️⃣ Fallback: ask Ollama with expert prompt
   llm_answer = call_ollama(question)
   return llm_answer or "No verified cybersecurity information found."

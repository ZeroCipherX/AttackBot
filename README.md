# AttackBot: Cybersecurity Assistant

AttackBot is a web-based cybersecurity assistant built with Django. It helps users understand and analyze CVEs (Common Vulnerabilities and Exposures), MITRE ATT&CK TTPs (Tactics, Techniques, and Procedures), and APT (Advanced Persistent Threat) groups using trusted datasets and advanced AI techniques. The assistant can answer questions, map relationships, and provide evidence from multiple sources, all through a modern chat interface.

## Features
- Natural language Q&A about CVEs, TTPs, and APTs
- Entity extraction for CVE, TTP, and APT IDs
- Data-driven answers from curated CSV datasets
- Semantic search using vector embeddings (FAISS + Sentence Transformers)
- LLM fallback (Ollama API, e.g., phi3, llama3, mistral)
- Evidence aggregation (CVSS, ExploitDB, CISA KEV)
- Modern, responsive chat UI with dark mode

## Project Structure
```
AttackBot/
├── manage.py
├── bot/
│   ├── admin.py
│   ├── apps.py
│   ├── bot_agent.py
│   ├── data_utils.py
│   ├── models.py
│   ├── tests.py
│   ├── vector_utils.py
│   ├── views.py
│   ├── templates/
│   │   └── chat.html
│   ├── static/
│   └── data/
│       ├── cves.csv
│       ├── cve_ttp_mapping.csv
│       ├── ttps.csv
│       ├── apt_ttp_mapping.csv
│       ├── apts.csv
│       ├── cvss.csv
│       ├── kev.csv
│       ├── Att&ckToCveMappings.csv
│       ├── exploits_mapped.csv
│       └── cve_ids.csv
├── AttackBot-backup/
│   ├── __init__.py
│   ├── asgi.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
```

## Requirements
- Python 3.8+
- Django 5.2+
- pandas
- numpy
- sentence-transformers
- faiss
- tqdm
- requests

Install dependencies (example):
```bash
pip install django pandas numpy sentence-transformers faiss-cpu tqdm requests
```

## Setup & Usage
1. **Clone the repository** and navigate to the project directory:
   ```bash
   git clone <repo-url>
   cd AttackBot
   ```
2. **Prepare datasets:**
   - Place the required CSV files in `AttackBot/bot/data/` (see list above).
3. **Build the vector index (optional, for semantic search):**
   ```bash
   python -c "from bot.vector_utils import build_index; build_index()"
   ```
4. **Run the Django server:**
   ```bash
   python manage.py runserver
   ```
5. **Access the web UI:**
   - Open [http://localhost:8000](http://localhost:8000) in your browser.
   - Ask questions about CVEs, TTPs, or APTs in the chat interface.

## LLM Integration (Optional)
- By default, the bot can call an Ollama LLM API (e.g., phi3, llama3, mistral) at `http://localhost:11434/api/generate`.
- To use this feature, ensure an Ollama server is running and accessible.
- You can change the model or endpoint in `bot/bot_agent.py`.

## Example Questions
- `Tell me about CVE-2021-34527`
- `What TTPs are linked to CVE-2022-12345?`
- `Which APTs use T1059?`
- `List CVEs related to PrintNightmare`

## License
See [LICENSE.md](LICENSE.md).

## Acknowledgments
- MITRE ATT&CK
- CISA KEV
- ExploitDB
- [Ollama](https://ollama.com/) for LLM API
- [Sentence Transformers](https://www.sbert.net/)
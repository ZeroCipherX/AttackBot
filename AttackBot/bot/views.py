from django.shortcuts import render
from django.http import JsonResponse
from .bot_agent import answer_question
from . import data_utils
import json, threading, re
from django.views.decorators.csrf import csrf_exempt

def is_greeting_or_smalltalk(question):
   q = question.lower()
   return any(word in q for word in ["hello", "hi", "hey", "what's up", "how are you"])

def is_purpose_question(question):
   q = question.lower()
   return "your purpose" in q or "what do you do" in q or "who are you" in q

def format_cve_response(details, cvss):
   parts = []
   if details:
       parts.append(f"🛡️ CVE Details:\n{details}")
   if cvss:
       parts.append(f"📋 CVSS:\n{cvss}")
   return "\n\n".join(parts)

@csrf_exempt
def chat_view(request):
   if request.method == "POST":
       data = json.loads(request.body)
       question = data.get("question", "")

       if not question.strip():
           return JsonResponse({"response": "Please enter a valid question."})

       if is_greeting_or_smalltalk(question):
           return JsonResponse({"response": "Hello! 👋 How can I help you with CVEs, TTPs, or APTs today?"})

       if is_purpose_question(question):
           return JsonResponse({"response": "I’m your Cybersecurity Assistant. I help you understand CVEs, TTPs, and APTs using trusted data from our database and verified web sources — no hallucinations!"})

       response, exception = None, None

       def llm_call():
           nonlocal response, exception
           try:
               response = answer_question(question)
           except Exception as e:
               exception = e

       thread = threading.Thread(target=llm_call)
       thread.start()
       thread.join(timeout=30)
       if thread.is_alive():
           return JsonResponse({"response": "⚠️ Sorry, I'm thinking too hard! Please try again in a moment."})
       if exception:
           return JsonResponse({"response": f"⚠️ Error processing question: {exception}"})

       cve_pattern = r"CVE-\d{4}-\d{4,7}"
       cve_ids = re.findall(cve_pattern, question, re.IGNORECASE)
       final_parts = [response] if response else []

       for cve_id in cve_ids:
           cve_details = data_utils.get_cve_details(cve_id)
           cvss_details = data_utils.get_cvss_details(cve_id)

           if cve_details or cvss_details:
               formatted = format_cve_response(cve_details, cvss_details)
               if formatted:
                   final_parts.append(formatted)

           evidence = data_utils.get_evidence_for_cve(cve_id)
           if evidence and 'exploitdb' in evidence:
               url = evidence['exploitdb'].get('url')
               if url:
                   final_parts.append(f"🚀 **Public exploit available**: [ExploitDB Link]({url})")

       full_response = "\n\n".join(final_parts) if final_parts else "🤔 Sorry, I couldn't find anything relevant."
       return JsonResponse({"response": full_response})

   return render(request, "chat.html")

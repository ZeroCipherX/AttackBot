import os
import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

def load_and_strip_csv(path):
   if os.path.exists(path):
       df = pd.read_csv(path)
       df.columns = df.columns.str.strip()
       return df
   return None

# Load datasets
cve_df = load_and_strip_csv(os.path.join(DATA_DIR, 'cves.csv'))
cve_ttp_df = load_and_strip_csv(os.path.join(DATA_DIR, 'cve_ttp_mapping.csv'))
ttp_df = load_and_strip_csv(os.path.join(DATA_DIR, 'ttps.csv'))
apt_ttp_df = load_and_strip_csv(os.path.join(DATA_DIR, 'apt_ttp_mapping.csv'))
cvss_df = load_and_strip_csv(os.path.join(DATA_DIR, 'cvss.csv'))
kev_df = load_and_strip_csv(os.path.join(DATA_DIR, 'kev.csv'))
attack_mapping_df = load_and_strip_csv(os.path.join(DATA_DIR, 'Att&ckToCveMappings.csv'))
exploits_mapped_df = load_and_strip_csv(os.path.join(DATA_DIR, 'exploits_mapped.csv'))
apts_df = load_and_strip_csv(os.path.join(DATA_DIR, 'apts.csv'))

def get_cve_details(cve_id):
   if cve_df is None: return None
   col = next((c for c in cve_df.columns if 'cve' in c.lower()), None)
   if not col: return None
   row = cve_df[cve_df[col].str.upper() == cve_id.upper()]
   return row.iloc[0].to_dict() if not row.empty else None

def get_ttps_for_cve(cve_id):
   results = set()
   if cve_ttp_df is not None:
       cve_col = next((c for c in cve_ttp_df.columns if 'cve' in c.lower()), None)
       ttp_col = next((c for c in cve_ttp_df.columns if 'ttp' in c.lower()), None)
       if cve_col and ttp_col:
           rows = cve_ttp_df[cve_ttp_df[cve_col].str.upper() == cve_id.upper()]
           for item in rows[ttp_col].dropna():
               results.update(t.strip() for t in str(item).split(';') if t.strip())
   if attack_mapping_df is not None:
       cve_col = next((c for c in attack_mapping_df.columns if 'cve' in c.lower()), None)
       ttp_cols = [c for c in attack_mapping_df.columns if 'impact' in c.lower() or 'technique' in c.lower()]
       if cve_col and ttp_cols:
           rows = attack_mapping_df[attack_mapping_df[cve_col].str.upper() == cve_id.upper()]
           for col in ttp_cols:
               for val in rows[col].dropna():
                   results.update(t.strip() for t in str(val).split(';') if t.strip())
   return list(results)

def get_apts_for_ttp(ttp_id):
   if apt_ttp_df is None: return []
   ttp_col = next((c for c in apt_ttp_df.columns if 'ttp' in c.lower()), None)
   apt_col = next((c for c in apt_ttp_df.columns if 'apt' in c.lower()), None)
   if not ttp_col or not apt_col: return []
   rows = apt_ttp_df[apt_ttp_df[ttp_col] == ttp_id]
   return list(rows[apt_col].unique()) if not rows.empty else []

def get_exploits_mapped(cve_id):
   if exploits_mapped_df is None: return []
   cve_col = next((c for c in exploits_mapped_df.columns if 'cve' in c.lower()), None)
   exploit_col = next((c for c in exploits_mapped_df.columns if 'exploit' in c.lower()), None)
   if not cve_col or not exploit_col: return []
   rows = exploits_mapped_df[exploits_mapped_df[cve_col].str.upper() == cve_id.upper()]
   return list(rows[exploit_col].unique()) if not rows.empty else []

def get_kev_details(cve_id):
   if kev_df is None: return None
   cve_col = next((c for c in kev_df.columns if 'cve' in c.lower()), None)
   if not cve_col: return None
   row = kev_df[kev_df[cve_col].str.upper() == cve_id.upper()]
   return row.iloc[0].to_dict() if not row.empty else None

def get_cvss_details(cve_id):
   if cvss_df is None: return None
   cve_col = next((c for c in cvss_df.columns if 'cve' in c.lower()), None)
   if not cve_col: return None
   row = cvss_df[cvss_df[cve_col].str.upper() == cve_id.upper()]
   return row.iloc[0].to_dict() if not row.empty else None

def get_attack_mapping(cve_id):
   if attack_mapping_df is None: return None
   cve_col = next((c for c in attack_mapping_df.columns if 'cve' in c.lower()), None)
   if not cve_col: return None
   row = attack_mapping_df[attack_mapping_df[cve_col].str.upper() == cve_id.upper()]
   return row.iloc[0].to_dict() if not row.empty else None

def get_ttp_details(ttp_id):
   if ttp_df is None: return None
   ttp_col = next((c for c in ttp_df.columns if 'ttp' in c.lower()), None)
   if not ttp_col: return None
   row = ttp_df[ttp_df[ttp_col] == ttp_id]
   return row.iloc[0].to_dict() if not row.empty else None

def get_apt_details(apt_id):
   if apts_df is None: return None
   apt_col = next((c for c in apts_df.columns if 'apt' in c.lower()), None)
   if not apt_col: return None
   row = apts_df[apts_df[apt_col] == apt_id]
   return row.iloc[0].to_dict() if not row.empty else None

def get_evidence_for_cve(cve_id):
   """
   Return evidence for a CVE from CVSS, Exploit-DB, and CISA KEV.
   """
   evidence = {}

   # CVSS
   if cvss_df is not None:
       cve_col = next((col for col in cvss_df.columns if 'cve' in col.lower()), None)
       if cve_col:
           row = cvss_df[cvss_df[cve_col].astype(str).str.upper() == cve_id.upper()]
           if not row.empty:
               evidence['cvss'] = row.iloc[0].to_dict()

   # Exploit-DB (actually exploits_mapped_df in this project)
   if exploits_mapped_df is not None:
       cve_col = next((col for col in exploits_mapped_df.columns if 'cve' in col.lower()), None)
       if cve_col:
           row = exploits_mapped_df[exploits_mapped_df[cve_col].astype(str).str.upper() == cve_id.upper()]
           if not row.empty:
               evidence['exploitdb'] = row.iloc[0].to_dict()

   # KEV
   if kev_df is not None:
       cve_col = next((col for col in kev_df.columns if 'cve' in col.lower()), None)
       if cve_col:
           row = kev_df[kev_df[cve_col].astype(str).str.upper() == cve_id.upper()]
           if not row.empty:
               evidence['kev'] = row.iloc[0].to_dict()

   return evidence
def search_cves_by_keyword(keyword, limit=3):
   """
   Search the CVE dataset for CVEs whose description contains the keyword.
   Returns a list of (cve_id, description) tuples.
   """
   if cve_df is None: return []
   cve_col = next((c for c in cve_df.columns if 'cve' in c.lower()), None)
   desc_col = next((c for c in cve_df.columns if 'desc' in c.lower()), None)
   if not cve_col or not desc_col: return []
   matches = cve_df[cve_df[desc_col].str.contains(keyword, case=False, na=False)]
   return list(zip(matches[cve_col], matches[desc_col]))[:limit]

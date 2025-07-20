import pandas as pd
from sentence_transformers import SentenceTransformer
import numpy as np
import faiss
import os
from tqdm import tqdm

DATASET_CSV = 'bot/data/cves.csv'
INDEX_PATH = 'bot/data/cve_index.faiss'
IDS_PATH = 'bot/data/cve_ids.csv'

# Load the model once
model = SentenceTransformer("all-MiniLM-L6-v2")

def build_index():
   df = pd.read_csv(DATASET_CSV)

   ids = df['CVE ID'].tolist()
   descriptions = df['Description'].fillna("").tolist()

   print(f"📋 Building FAISS index for {len(ids)} CVEs…")

   # Batched + parallel encoding
   embeddings = model.encode(
       descriptions,
       convert_to_numpy=True,
       batch_size=128,
       show_progress_bar=True,
       normalize_embeddings=True  # optional, but good for cosine similarity
   )

   dim = embeddings.shape[1]
   print(f"📐 Embedding dimension: {dim}")

   # Use an efficient FAISS index
   index = faiss.IndexFlatIP(dim)  # inner product = cosine if normalized
   index.add(embeddings)

   faiss.write_index(index, INDEX_PATH)
   pd.Series(ids).to_csv(IDS_PATH, index=False, header=False)

   print(f"✅ Done! Indexed {len(ids)} CVEs. Saved to:")
   print(f"   🔗 {INDEX_PATH}")
   print(f"   🔗 {IDS_PATH}")
def search_cve(query, top_k=3):
   if not os.path.exists(INDEX_PATH) or not os.path.exists(IDS_PATH):
       raise RuntimeError("Index or IDs file not found. Run build_index() first.")

   # Load index and IDs
   index = faiss.read_index(INDEX_PATH)
   ids = pd.read_csv(IDS_PATH, header=None)[0].tolist()
   df = pd.read_csv(DATASET_CSV).set_index('CVE ID')

   # Embed the query
   query_emb = model.encode([query], convert_to_numpy=True, normalize_embeddings=True)

   # Search
   D, I = index.search(query_emb, top_k)

   results = []
   for idx in I[0]:
       cve_id = ids[idx]
       desc = df.loc[cve_id]['Description']
       results.append((cve_id, desc))

   return results

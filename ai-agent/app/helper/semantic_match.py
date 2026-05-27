from sentence_transformers import SentenceTransformer, util

# Tải mô hình local (chạy rất nhanh, không tốn token gọi API)
embedder = SentenceTransformer('all-MiniLM-L6-v2')

def semantic_match(field1: str, field2: str, threshold: float = 0.5) -> bool:
    """So sánh độ tương đồng ngữ nghĩa của 2 field"""
    embeddings1 = embedder.encode(field1)
    embeddings2 = embedder.encode(field2)
    cosine_score = util.cos_sim(embeddings1, embeddings2).item()
    
    return cosine_score >= threshold
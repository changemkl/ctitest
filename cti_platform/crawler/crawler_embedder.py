import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
from sentence_transformers import SentenceTransformer
import numpy as np
from datetime import datetime
import hashlib


# MongoDB连接设置
mongo_client = MongoClient("mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin", server_api=ServerApi('1'))
db = mongo_client["cti_platform"]
collection = db["external_threats"]

# 向量模型加载
model = SentenceTransformer('all-MiniLM-L6-v2')

# 示例网页列表（可替换为你想抓的页面）
TARGET_URLS = [
    "https://www.example-threat-blog.com/article1",
    "https://www.example-threat-blog.com/article2"
]

def fetch_and_process(url):
    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        # 获取标题和正文
        title = soup.title.text.strip() if soup.title else "No Title"
        content_tags = soup.find_all(["p", "div"])
        content = " ".join(tag.get_text().strip() for tag in content_tags if tag.get_text())

        if not content:
            return None

        # 计算向量
        embedding = model.encode(content)

        # 构建唯一ID
        uid = hashlib.sha256(url.encode()).hexdigest()

        return {
            "_id": uid,
            "title": title,
            "url": url,
            "content": content,
            "embedding": embedding.tolist(),  # MongoDB不支持np.ndarray直接存储
            "timestamp": datetime.utcnow(),
            "source": "custom_crawler"
        }

    except Exception as e:
        print(f"[ERROR] Failed to fetch/process {url}: {e}")
        return None

def main():
    for url in TARGET_URLS:
        data = fetch_and_process(url)
        if data:
            try:
                collection.replace_one({"_id": data["_id"]}, data, upsert=True)
                print(f"[OK] Inserted: {data['title']}")
            except Exception as db_err:
                print(f"[DB ERROR] {db_err}")

if __name__ == "__main__":
    main()

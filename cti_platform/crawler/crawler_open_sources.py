import requests
from datetime import datetime, timezone
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from sentence_transformers import SentenceTransformer
import numpy as np
import faiss

# ======================== 配置 ========================
OPENCTI_API_URL = "https://demo.opencti.io/graphql"
OPENCTI_TOKEN = "71b92162-9a24-442a-ba5c-481e45cd509a"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {OPENCTI_TOKEN}"
}

# MongoDB
client = MongoClient("mongodb+srv://yzhang850:a237342160@cluster0.cficuai.mongodb.net/?retryWrites=true&w=majority&authSource=admin", server_api=ServerApi('1'))
db = client["cti_platform"]
threats_col = db["threats"]

# 语义向量模型
model = SentenceTransformer("all-MiniLM-L6-v2")
opencti_index = None
opencti_entries = []

# ======================== GraphQL 查询 ========================
GRAPHQL_QUERY = """
# 3. 管理员查询 (admin)
query FullThreatGraphUnified {
  intrusionSets(first: 100) {
    edges {
      node {
        id
        name
        description
        objectLabel {
          value
        }

        intrusionSetCountryRelations: stixCoreRelationships(toTypes: ["Country"]) {
          edges {
            node {
              to {
                ... on Country {
                  id
                  name
                  latitude
                  longitude
                }
              }
            }
          }
        }

        identityRelations: stixCoreRelationships(toTypes: ["Identity"]) {
          edges {
            node {
              to {
                ... on Identity {
                  id
                  name
                  identity_class
                  description
                }
              }
            }
          }
        }

        malwareRelations: stixCoreRelationships(
          toTypes: ["Malware"]
          relationship_type: "uses"
        ) {
          edges {
            node {
              to {
                ... on Malware {
                  id
                  name
                  description
                  malware_types
                  first_seen
                  last_seen

                  vulnerabilityRelations: stixCoreRelationships(
                    toTypes: ["Vulnerability"]
                    relationship_type: "exploits"
                  ) {
                    edges {
                      node {
                        to {
                          ... on Vulnerability {
                            id
                            name
                            description
                            x_opencti_cvss_base_score
                            created
                          }
                        }
                      }
                    }
                  }

                  countryRelations: stixCoreRelationships(
                    toTypes: ["Country"]
                    relationship_type: "targets"
                  ) {
                    edges {
                      node {
                        to {
                          ... on Country {
                            id
                            name
                            latitude
                            longitude
                          }
                        }
                      }
                    }
                  }

                  identityRelations: stixCoreRelationships(toTypes: ["Identity"]) {
                    edges {
                      node {
                        to {
                          ... on Identity {
                            id
                            name
                            identity_class
                            description
                          }
                        }
                      }
                    }
                  }

                  attackPatternRelations: stixCoreRelationships(
                    toTypes: ["AttackPattern"]
                    relationship_type: "uses"
                  ) {
                    edges {
                      node {
                        to {
                          ... on AttackPattern {
                            id
                            name
                            description
                          }
                        }
                      }
                    }
                  }

                  toolRelations: stixCoreRelationships(
                    toTypes: ["Tool"]
                    relationship_type: "uses"
                  ) {
                    edges {
                      node {
                        to {
                          ... on Tool {
                            id
                            name
                            description
                            tool_types
                          }
                        }
                      }
                    }
                  }

                  infrastructureRelations: stixCoreRelationships(
                    toTypes: ["Infrastructure"]
                  ) {
                    edges {
                      node {
                        to {
                          ... on Infrastructure {
                            id
                            name
                            description
                          }
                        }
                      }
                    }
                  }

                  reports(first: 5) {
                    edges {
                      node {
                        id
                        name
                        published
                        description
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

"""

def fetch_graph():
    res = requests.post(OPENCTI_API_URL, headers=HEADERS, json={"query": GRAPHQL_QUERY})
    res.raise_for_status()
    return res.json()

def save_threat(entry):
    title = entry.get("title", "")
    content = entry.get("content", "")
    if not title or not content:
        return
    # 查重
    if threats_col.find_one({"title": title, "content": content}):
        return
    embedding = model.encode([f"{title}. {content}"])[0].tolist()
    entry["embedding"] = embedding
    threats_col.insert_one(entry)
    print("[SAVE]", title)

def parse_and_save(data):
    sets = data.get("data", {}).get("intrusionSets", {}).get("edges", [])
    for edge in sets:
        intrusion = edge["node"]
        intrusion_name = intrusion.get("name", "Unnamed IntrusionSet")

        malwares = intrusion.get("malwareRelations", {}).get("edges", [])
        for m in malwares:
            malware = m["node"].get("to", {})
            if not malware:
                continue

            country_edges = malware.get("countryRelations", {}).get("edges", [])
            identity_edges = malware.get("identityRelations", {}).get("edges", [])
            vuln_edges = malware.get("vulnerabilityRelations", {}).get("edges", [])
            report_edges = malware.get("reports", {}).get("edges", [])

            # 提取对应节点
            countries = [c["node"]["to"] for c in country_edges if c.get("node")]
            identities = [i["node"]["to"] for i in identity_edges if i.get("node")]
            vulns = [v["node"]["to"] for v in vuln_edges if v.get("node")]
            reports = [r["node"] for r in report_edges if r.get("node")]

            entry = {
                "title": malware.get("name", "Unnamed Malware"),
                "source": "OpenCTI",
                "timestamp": datetime.now(timezone.utc),
                "content": malware.get("description", ""),
                "location": countries[0]["name"] if countries else "Unknown",
                "tags": ["malware", "intrusionSet"],
                "entities": {
                    "intrusionSet": intrusion,
                    "malware": malware,
                    "countries": countries,
                    "identities": identities,
                    "vulnerabilities": vulns,
                    "reports": reports,
                }
            }
            save_threat(entry)


def build_index():
    entries = list(threats_col.find({"embedding": {"$exists": True}}).limit(1000))
    if not entries:
        return None, []
    vecs = np.array([e["embedding"] for e in entries]).astype("float32")
    idx = faiss.IndexFlatL2(vecs.shape[1])
    idx.add(vecs)
    return idx, entries

def recommend(threat, top_k=3):
    global opencti_index, opencti_entries
    if not threat.get("embedding") or opencti_index is None:
        return []
    vec = np.array(threat["embedding"]).reshape(1, -1).astype("float32")
    _, ids = opencti_index.search(vec, top_k + 1)
    recs = []
    for i in ids[0]:
        if i < len(opencti_entries):
            candidate = opencti_entries[i]
            if candidate["_id"] != threat["_id"]:
                recs.append({"title": candidate["title"], "source": candidate.get("source", "OpenCTI")})
        if len(recs) >= top_k:
            break
    return recs

if __name__ == "__main__":
    print("🚀 Querying OpenCTI full graph...")
    raw = fetch_graph()
    parse_and_save(raw)

    print("📦 Building index...")
    opencti_index, opencti_entries = build_index()

    print("💾 Saving recommendations...")
    for threat in opencti_entries:
        threats_col.update_one({"_id": threat["_id"]}, {"$set": {"recommendations": recommend(threat)}})

    print("✅ All done.")

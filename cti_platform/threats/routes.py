# cti_platform/threats/routes.py
from flask import Blueprint, render_template, request, abort
from flask_login import login_required, current_user
from database.mongo import db
from collections import Counter

threat_bp = Blueprint("threat", __name__, url_prefix="/threats")

# ---- 角色等级（用于访问控制）----
ROLE_ORDER = {"public": 1, "pro": 2, "admin": 3}

# ---- 从 STIX 提取 indicators 并分组 ----
def stix_extract_indicators(stix_bundle: dict):
    inds = []
    if not stix_bundle:
        return inds
    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern") or ""
        if "[domain-name:value" in pattern:
            ioc_type = "domain"
        elif "[url:value" in pattern:
            ioc_type = "url"
        else:
            ioc_type = "other"
        inds.append(
            {
                "id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "pattern": pattern,
                "valid_from": obj.get("valid_from"),
                "ioc_type": ioc_type,
            }
        )
    return inds

# ---- Mongo 文档 -> 视图模型（模板直用）----
def to_view_model(doc: dict):
    entities = doc.get("entities") or {}
    indicators = stix_extract_indicators(doc.get("stix_bundle") or {})
    groups = {"domain": [], "url": [], "other": []}
    for i in indicators:
        groups[i["ioc_type"]].append(i)

    return {
        "id": str(doc.get("_id")),
        "title": doc.get("title") or "Untitled",
        "source": doc.get("source") or "Unknown",
        "url": doc.get("url"),
        "published": doc.get("timestamp"),
        "updated_at": doc.get("updated_at"),
        "content_html": (doc.get("content") or ""),
        "cves": entities.get("cve", []) or [],
        "indicator_groups": groups,
        "indicator_count": len(indicators),
    }

# ---- 统一查询 + 渲染（被三个角色端点复用）----
def _render_for_role(role_view: str):
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 10))
    search = (request.args.get("search") or "").strip()

    query = {}
    if search:
        query["title"] = {"$regex": search, "$options": "i"}



    total = db["threats"].count_documents(query)
    cursor = (
        db["threats"]
        .find(
            query,
            {
                "title": 1,
                "source": 1,
                "url": 1,
                "timestamp": 1,
                "updated_at": 1,
                "entities": 1,
                "stix_bundle": 1,
                "content": 1,
                "location": 1,
            },
        )
        .sort("timestamp", -1)
        .skip((page - 1) * size)
        .limit(size)
    )
    docs = list(cursor)
    items = [to_view_model(d) for d in docs]

    # 统计（如需性能可做缓存）
    agg_cursor = db["threats"].find(query, {"source": 1, "location": 1})
    source_stats = Counter()
    location_stats = Counter()
    for t in agg_cursor:
        source_stats[t.get("source", "Unknown")] += 1
        location_stats[t.get("location", "Unknown")] += 1

    return render_template(
        "threats.html",
        items=items,
        role_view=role_view,
        page=page,
        size=size,
        total=total,
        search=search,
        source_stats=dict(source_stats),
        location_stats=dict(location_stats),
        title=f"Threat Intelligence ({role_view.capitalize()})",
    )

# ---- 路由 ----

@threat_bp.route("/", methods=["GET"], endpoint="view_threats")
@login_required
def index():
    """
    根路径（兼容 url_for('threat.view_threats')）：
    - 默认按当前用户角色渲染
    - 支持 ?role_view=public|pro|admin 覆盖
    """
    role_view = request.args.get("role_view") or getattr(current_user, "role", "public")
    return _render_for_role(role_view)

@threat_bp.route("/public", methods=["GET"])
@login_required
def view_public():
    return _render_for_role("public")

@threat_bp.route("/pro", methods=["GET"])
@login_required
def view_pro():
    user_role = getattr(current_user, "role", "public")
    if ROLE_ORDER.get(user_role, 0) < ROLE_ORDER["pro"]:
        return abort(403)
    return _render_for_role("pro")
@threat_bp.route("/_debug/db")
def _debug_db():
    try:
        names = db.list_collection_names()
        count = db["threats"].estimated_document_count() if "threats" in names else 0
        sample = db["threats"].find_one({}, {"_id": 0, "title": 1, "source": 1, "timestamp": 1}) if count else None
        return {"ok": True, "collections": names, "threats_count": int(count), "sample": sample}
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500

@threat_bp.route("/admin", methods=["GET"])
@login_required
def view_admin():
    if getattr(current_user, "role", "public") != "admin":
        return abort(403)
    return _render_for_role("admin")

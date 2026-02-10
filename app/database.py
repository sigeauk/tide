import duckdb
import json
import os
from log import log_info, log_error, log_debug
import pandas as pd
import time
from datetime import datetime

# --- CONFIG ---
DB_PATH = "/app/data/tide.duckdb"
TRIGGER_DIR = "/app/data/triggers"
SCHEMA_VERSION = 3  # Increment this when adding migrations


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
                log_info(f"⚠️ DB Locked. Retrying connection ({attempt}/{retries})...")
                time.sleep(delay)
            else:
                raise e
        except Exception as e:
            log_error(f"DB Connection failed: {e}")
            raise e
    
    log_error("❌ DB Timeout: Could not acquire lock.")
    raise duckdb.IOException("Database locked by another process.")

def get_schema_version(conn):
    """Get current schema version from database."""
    try:
        # Check if schema_version table exists (DuckDB uses information_schema)
        result = conn.execute("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_name = 'schema_version'
        """).fetchone()
        
        if result:
            version = conn.execute("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1").fetchone()
            return version[0] if version else 0
        return 0
    except:
        # Fallback: try to query directly (table might exist but info_schema query failed)
        try:
            version = conn.execute("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1").fetchone()
            return version[0] if version else 0
        except:
            return 0

def set_schema_version(conn, version):
    """Record schema version in database."""
    try:
        # Create schema_version table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP
            )
        """)
        # Insert or update version using DuckDB's now() function
        conn.execute("""
            INSERT INTO schema_version (version, applied_at)
            VALUES (?, now())
            ON CONFLICT (version) DO UPDATE SET applied_at = now()
        """, [version])
    except Exception as e:
        log_error(f"Failed to set schema version: {e}")

def run_migrations(conn):
    """Run database migrations based on current schema version."""
    current_version = get_schema_version(conn)
    target_version = SCHEMA_VERSION
    
    if current_version >= target_version:
        return  # Already up to date
    
    log_info(f"🔄 Running database migrations from version {current_version} to {target_version}...")
    
    # Migration 1: Initial schema (v0 -> v1)
    if current_version < 1:
        try:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_actors (
                name VARCHAR PRIMARY KEY,
                description VARCHAR,
                ttps VARCHAR[],
                ttp_count INTEGER,
                aliases VARCHAR,
                origin VARCHAR,
                last_updated TIMESTAMP
            )
        """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id VARCHAR PRIMARY KEY,
                name VARCHAR,
                severity VARCHAR,
                author VARCHAR,
                enabled INTEGER,
                space VARCHAR,
                score INTEGER,
                quality_score INTEGER,
                meta_score INTEGER,
                score_mapping INTEGER,
                score_field_type INTEGER,
                score_search_time INTEGER,
                score_language INTEGER,
                score_note INTEGER,
                score_override INTEGER,
                score_tactics INTEGER,
                score_techniques INTEGER,
                score_author INTEGER,
                score_highlights INTEGER,
                last_updated TIMESTAMP,
                mitre_ids VARCHAR[], 
                raw_data JSON
            )
        """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                id VARCHAR PRIMARY KEY,
                name VARCHAR,
                tactic VARCHAR,
                url VARCHAR
            )
        """)
            set_schema_version(conn, 1)
            log_info("✅ Migration 1 completed: Initial schema created")
        except Exception as e:
            log_error(f"Migration 1 failed: {e}")
            raise
    
    # Migration 2: Add source column to threat_actors (v1 -> v2)
    if current_version < 2:
        try:
            # Check if source column exists and has wrong type
            cols = conn.execute("DESCRIBE threat_actors").fetchall()
            source_col = next((c for c in cols if c[0] == 'source'), None)
            
            if source_col and source_col[1] == 'VARCHAR':
                # Source column exists but has wrong type - need to fix
                log_info("🔄 Converting source column from VARCHAR to VARCHAR[]...")
                # Create temp column, migrate data, drop old, rename new
                conn.execute("ALTER TABLE threat_actors ADD COLUMN source_new VARCHAR[]")
                # Convert existing string values to single-element arrays
                conn.execute("""
                    UPDATE threat_actors 
                    SET source_new = CASE 
                        WHEN source IS NOT NULL AND source != '' THEN [source]
                        ELSE []
                    END
                """)
                conn.execute("ALTER TABLE threat_actors DROP COLUMN source")
                conn.execute("ALTER TABLE threat_actors RENAME COLUMN source_new TO source")
                log_info("✅ Migration 2: Converted source column to VARCHAR[]")
            elif source_col is None:
                # Add source column if it doesn't exist
                conn.execute("ALTER TABLE threat_actors ADD COLUMN source VARCHAR[]")
                log_info("✅ Migration 2: Added source column to threat_actors")
            else:
                log_info("✅ Migration 2: Source column already correct type")
            
            set_schema_version(conn, 2)
        except Exception as e:
            log_error(f"Migration 2 failed: {e}")
            raise
    
    # Migration 3: Change detection_rules PK to composite (rule_id, space) (v2 -> v3)
    if current_version < 3:
        try:
            # Drop and recreate detection_rules with new composite PK
            # Data is ephemeral (live feed from Elastic) so no need to preserve
            log_info("🔄 Recreating detection_rules table with new schema...")
            conn.execute("DROP TABLE IF EXISTS detection_rules")
            conn.execute("""
                CREATE TABLE detection_rules (
                    rule_id VARCHAR,
                    name VARCHAR,
                    severity VARCHAR,
                    author VARCHAR,
                    enabled INTEGER,
                    space VARCHAR,
                    score INTEGER,
                    quality_score INTEGER,
                    meta_score INTEGER,
                    score_mapping INTEGER,
                    score_field_type INTEGER,
                    score_search_time INTEGER,
                    score_language INTEGER,
                    score_note INTEGER,
                    score_override INTEGER,
                    score_tactics INTEGER,
                    score_techniques INTEGER,
                    score_author INTEGER,
                    score_highlights INTEGER,
                    last_updated TIMESTAMP,
                    mitre_ids VARCHAR[], 
                    raw_data JSON,
                    PRIMARY KEY (rule_id, space)
                )
            """)
            set_schema_version(conn, 3)
            log_info("✅ Migration 3 completed: Recreated detection_rules with PK (rule_id, space)")
        except Exception as e:
            log_error(f"Migration 3 failed: {e}")
            raise
    
    log_info(f"✅ Database migrations complete. Schema version: {target_version}")

def init_db():
    """Initialize database and run migrations."""
    os.makedirs(TRIGGER_DIR, exist_ok=True)
    conn = get_connection(read_only=False)
    try:
        # Run migrations to ensure schema is up to date
        run_migrations(conn)
        log_info("🦆 DuckDB Initialized.")
    except Exception as e:
        log_error(f"Init DB Failed: {e}")
        raise
    finally:
        conn.close()

# --- INGESTION HELPERS ---

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

# --- INGESTION (Worker Only) ---

def clear_threat_actors():
    """Clear all threat actors for a fresh live sync."""
    conn = get_connection(read_only=False)
    try:
        count = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
        conn.execute("DELETE FROM threat_actors WHERE 1=1")
        log_info(f"Cleared {count} threat actors")
        return count
    except Exception as e:
        log_error(f"Clear threat actors failed: {e}")
        return 0
    finally:
        conn.close()

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

def save_mitre_definitions(df):
    if df.empty: return
    conn = get_connection(read_only=False)
    try:
        df.columns = [c.lower().strip() for c in df.columns]
        
        # --- CRITICAL FIX 1: Map helper columns to DB columns ---
        renames = {'technique_id': 'id', 'technique_name': 'name'}
        df.rename(columns=renames, inplace=True)
        
        target_cols = ['id', 'name', 'tactic', 'url']
        df_final = ensure_columns(df, target_cols)
        
        conn.register('mitre_source', df_final)
        
        # --- CRITICAL FIX 2: Update 'tactic' on conflict ---
        conn.execute("""
            INSERT INTO mitre_techniques (id, name, tactic, url)
            SELECT id, name, tactic, url FROM mitre_source
            ON CONFLICT (id) DO UPDATE SET 
                name = EXCLUDED.name,
                tactic = EXCLUDED.tactic 
        """)
    except Exception as e:
        log_error(f"Save MITRE Defs Failed: {e}")
    finally:
        conn.close()

def save_audit_results(audit_list):
    if not audit_list: return 0
    df = pd.DataFrame(audit_list)
    
    df['enabled'] = df['enabled'].apply(lambda x: 1 if x else 0)
    
    # Parse author - handle list format like "['darral']" -> "darral"
    def parse_author(val):
        if not val or val == '❌':
            return '❌'
        s = str(val).strip()
        if s.startswith('[') and s.endswith(']'):
            inner = s[1:-1]
            authors = [a.strip().strip("'").strip('"') for a in inner.split(',') if a.strip()]
            return ', '.join(authors) if authors else '❌'
        return s if s else '❌'
    
    df['author'] = df['author_str'].apply(parse_author) if 'author_str' in df.columns else '❌'
    df['space'] = df['space_id'].fillna('default') if 'space_id' in df.columns else 'default'
    df['last_updated'] = datetime.now()
    df['mitre_ids'] = df['mitre_ids'].apply(lambda x: x if isinstance(x, list) else [])
    
    # Build raw_data to include both the original rule AND the field mapping results
    def build_raw_data(row):
        raw = row.get('raw_data', {})
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except:
                raw = {}
        # Merge in the field mapping results so UI can display them
        raw['results'] = row.get('results', [])
        raw['query'] = row.get('query', '')
        return json.dumps(raw, default=str)
    
    df['raw_data'] = df.apply(build_raw_data, axis=1)

    target_cols = [
        'rule_id', 'name', 'severity', 'author', 'enabled', 'space',
        'score', 'quality_score', 'meta_score',
        'score_mapping', 'score_field_type', 'score_search_time', 
        'score_language', 'score_note', 'score_override', 'score_tactics',
        'score_techniques', 'score_author', 'score_highlights',
        'last_updated', 'mitre_ids', 'raw_data'
    ]
    df_final = ensure_columns(df, target_cols)
    
    # Check for duplicates within the incoming data (same rule_id + space)
    duplicates = df_final[df_final.duplicated(subset=['rule_id', 'space'], keep='first')]
    if not duplicates.empty:
        dup_names = duplicates['name'].tolist()
        log_info(f"⚠️ Skipping {len(dup_names)} duplicate rules (same rule_id + space): {dup_names[:5]}{'...' if len(dup_names) > 5 else ''}")
        # Keep only first occurrence of each rule_id + space combo
        df_final = df_final.drop_duplicates(subset=['rule_id', 'space'], keep='first')

    conn = get_connection(read_only=False)
    try:
        # Clear existing data - use DELETE which is more reliable
        conn.execute("DELETE FROM detection_rules WHERE 1=1")
        conn.execute("CHECKPOINT")
        
        # Insert fresh data with ON CONFLICT to handle any edge cases
        conn.register('rules_source', df_final)
        conn.execute("""
            INSERT INTO detection_rules 
            SELECT * FROM rules_source
            ON CONFLICT (rule_id, space) DO UPDATE SET
                name = EXCLUDED.name,
                severity = EXCLUDED.severity,
                author = EXCLUDED.author,
                enabled = EXCLUDED.enabled,
                score = EXCLUDED.score,
                quality_score = EXCLUDED.quality_score,
                meta_score = EXCLUDED.meta_score,
                score_mapping = EXCLUDED.score_mapping,
                score_field_type = EXCLUDED.score_field_type,
                score_search_time = EXCLUDED.score_search_time,
                score_language = EXCLUDED.score_language,
                score_note = EXCLUDED.score_note,
                score_override = EXCLUDED.score_override,
                score_tactics = EXCLUDED.score_tactics,
                score_techniques = EXCLUDED.score_techniques,
                score_author = EXCLUDED.score_author,
                score_highlights = EXCLUDED.score_highlights,
                last_updated = EXCLUDED.last_updated,
                mitre_ids = EXCLUDED.mitre_ids,
                raw_data = EXCLUDED.raw_data
        """)
        
        # Force checkpoint to flush data to disk immediately
        conn.execute("CHECKPOINT")
        
        # Verify insertion
        verify_count = conn.execute("SELECT COUNT(*) as cnt FROM detection_rules").fetchall()[0][0]
        log_info(f"✅ Saved {verify_count} rules to database")
        
        return len(df_final)
    except Exception as e:
        log_error(f"Save Rules Failed: {e}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
        return 0
    finally:
        conn.close()

# --- ANALYTICS ---

def get_latest_rules():
    # Ensure database exists
    try:
        init_db()
    except:
        pass
    
    # Use read_only=False to ensure we see the latest committed data
    conn = get_connection(read_only=False)
    try:
        # Force a checkpoint to ensure we're reading committed data
        try:
            conn.execute("CHECKPOINT")
        except:
            pass
        
        df = conn.execute("SELECT * FROM detection_rules ORDER BY score ASC").df()
        try: last_sync = df['last_updated'].max().strftime("%Y-%m-%d %H:%M")
        except: last_sync = "Never"
        
        # Convert numpy arrays to Python lists (DuckDB returns arrays as numpy)
        if 'mitre_ids' in df.columns:
            df['mitre_ids'] = df['mitre_ids'].apply(lambda x: list(x) if hasattr(x, 'tolist') else (x if isinstance(x, list) else []))
        
        records = df.to_dict('records')
        return records, last_sync
    except Exception as e:
        log_error(f"Get Latest Rules Failed: {e}")
        return [], "Never"
    finally: 
        conn.close()

def wait_for_sync(timeout=30):
    """Wait for sync to complete by checking if rules were updated AFTER trigger time."""
    import time
    
    # Ensure database exists first
    try:
        init_db()
    except:
        pass
    
    try:
        # Get the time right now (when sync was triggered)
        trigger_time = datetime.now()
        log_info(f"Waiting for sync triggered at {trigger_time}...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(0.5)
            try:
                conn = get_connection(read_only=True)
                # Check if any rules have been updated AFTER the trigger time
                recent_rules = conn.execute(
                    "SELECT COUNT(*) as cnt FROM detection_rules WHERE last_updated > ?", 
                    [trigger_time]
                ).fetchall()
                conn.close()
                
                recent_count = recent_rules[0][0]
                # If we have at least one rule updated after trigger, sync is complete
                if recent_count > 0:
                    log_info(f"✓ Sync completed, {recent_count} rules updated")
                    return True
            except Exception as e:
                log_debug(f"Still waiting... {str(e)[:50]}")
        
        log_debug(f"⚠ Timeout waiting for sync (no updates within {timeout}s)")
        return False
    except Exception as e:
        log_error(f"Wait for sync failed: {e}")
        return False

def get_threat_data():
    conn = get_connection(read_only=False)
    try:
        try:
            conn.execute("CHECKPOINT")
        except:
            pass
        df = conn.execute("SELECT * FROM threat_actors ORDER BY ttp_count DESC").df()
        return df.to_dict('records'), "Automated"
    except: return [], "Error"
    finally: conn.close()

def get_coverage_analysis(actor_name=None):
    conn = get_connection(read_only=True)
    try:
        if actor_name:
            query = """
            WITH actor_ttps AS (
                SELECT unnest(ttps) as t_id FROM threat_actors WHERE name = ?
            ),
            defensive_coverage AS (
                SELECT DISTINCT unnest(mitre_ids) as t_id FROM detection_rules WHERE enabled = 1
            )
            SELECT 
                a.t_id, m.name as technique_name,
                CASE WHEN d.t_id IS NOT NULL THEN 'Green' ELSE 'Red' END as status
            FROM actor_ttps a
            LEFT JOIN defensive_coverage d ON a.t_id = d.t_id
            LEFT JOIN mitre_techniques m ON a.t_id = m.id
            """
            return conn.execute(query, [actor_name]).df()
        return pd.DataFrame()
    except: return pd.DataFrame()
    finally: conn.close()

# --- TRIGGERS ---

def set_trigger(trigger_name):
    try:
        path = os.path.join(TRIGGER_DIR, trigger_name)
        with open(path, 'w') as f: f.write("1")
    except Exception as e: log_error(f"Failed to set trigger: {e}")

def check_and_clear_trigger(trigger_name):
    path = os.path.join(TRIGGER_DIR, trigger_name)
    if os.path.exists(path):
        try: os.remove(path); return True
        except: return False
    return False

# --- TABLE MANAGEMENT ---

def clear_detection_rules():
    """Clear all detection rules from the database. Returns count of deleted rows."""
    conn = get_connection(read_only=False)
    try:
        count = conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
        conn.execute("DELETE FROM detection_rules WHERE 1=1")
        conn.execute("CHECKPOINT")
        log_info(f"🗑️ Cleared {count} detection rules from database")
        return count
    except Exception as e:
        log_error(f"Clear Detection Rules Failed: {e}")
        return 0
    finally:
        conn.close()

def clear_threat_actors():
    """Clear all threat actors from the database. Returns count of deleted rows."""
    conn = get_connection(read_only=False)
    try:
        count = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
        conn.execute("DELETE FROM threat_actors WHERE 1=1")
        conn.execute("CHECKPOINT")
        log_info(f"🗑️ Cleared {count} threat actors from database")
        return count
    except Exception as e:
        log_error(f"Clear Threat Actors Failed: {e}")
        return 0
    finally:
        conn.close()

def get_all_covered_ttps():
    conn = get_connection(read_only=False)
    try:
        try:
            conn.execute("CHECKPOINT")
        except:
            pass
        result = conn.execute("SELECT DISTINCT unnest(mitre_ids) FROM detection_rules WHERE enabled = 1").fetchall()
        return {row[0] for row in result if row[0]}
    except: return set()
    finally: conn.close()

def get_technique_map():
    conn = get_connection(read_only=True)
    try:
        result = conn.execute("SELECT id, tactic FROM mitre_techniques").fetchall()
        return {row[0]: row[1] for row in result if row[0] and row[1]}
    except: return {}
    finally: conn.close()

def get_technique_names():
    """Get a map of technique IDs to their names."""
    conn = get_connection(read_only=True)
    try:
        result = conn.execute("SELECT id, name FROM mitre_techniques").fetchall()
        return {row[0]: row[1] for row in result if row[0] and row[1]}
    except: return {}
    finally: conn.close()

def get_rule_health_metrics(validation_file="data/checkedRule.json"):
    """Calculate comprehensive rule health metrics.
    
    Returns dict with:
    - total_rules, enabled_rules, disabled_rules
    - avg_score, min_score, max_score
    - rules_by_space: {space: count}
    - validated_count, validation_expired_count (>12 weeks)
    - severity_breakdown: {severity: count}
    - language_breakdown: {language: count}
    - low_quality_count (score < 50)
    - high_quality_count (score >= 80)
    """
    from datetime import datetime
    import os
    
    conn = get_connection(read_only=False)
    try:
        try:
            conn.execute("CHECKPOINT")
        except:
            pass
        
        df = conn.execute("SELECT * FROM detection_rules").df()
        
        if df.empty:
            return {
                'total_rules': 0, 'enabled_rules': 0, 'disabled_rules': 0,
                'avg_score': 0, 'min_score': 0, 'max_score': 0,
                'rules_by_space': {}, 'validated_count': 0, 'validation_expired_count': 0,
                'never_validated_count': 0, 'severity_breakdown': {}, 'language_breakdown': {},
                'low_quality_count': 0, 'high_quality_count': 0
            }
        
        # Basic counts
        total_rules = len(df)
        enabled_rules = len(df[df['enabled'] == 1])
        disabled_rules = total_rules - enabled_rules
        
        # Score stats
        avg_score = float(df['score'].mean()) if 'score' in df.columns else 0
        min_score = int(df['score'].min()) if 'score' in df.columns else 0
        max_score = int(df['score'].max()) if 'score' in df.columns else 0
        
        # Quality tiers
        low_quality_count = len(df[df['score'] < 50]) if 'score' in df.columns else 0
        high_quality_count = len(df[df['score'] >= 80]) if 'score' in df.columns else 0
        
        # Rules by space
        rules_by_space = {}
        if 'space' in df.columns:
            space_counts = df['space'].value_counts().to_dict()
            rules_by_space = {str(k): int(v) for k, v in space_counts.items()}
        
        # Severity breakdown
        severity_breakdown = {}
        if 'severity' in df.columns:
            sev_counts = df['severity'].value_counts().to_dict()
            severity_breakdown = {str(k): int(v) for k, v in sev_counts.items()}
        
        # Language breakdown (from raw_data)
        language_breakdown = {}
        if 'raw_data' in df.columns:
            try:
                langs = df['raw_data'].apply(lambda x: json.loads(x).get('language', 'unknown') if x else 'unknown')
                lang_counts = langs.value_counts().to_dict()
                language_breakdown = {str(k): int(v) for k, v in lang_counts.items()}
            except:
                pass
        
        # Validation stats
        validated_count = 0
        validation_expired_count = 0
        
        if os.path.exists(validation_file):
            try:
                with open(validation_file, 'r') as f:
                    val_data = json.load(f).get('rules', {})
                
                now = datetime.now()
                for rule_name in df['name'].tolist():
                    rule_v = val_data.get(str(rule_name), {})
                    if rule_v:
                        validated_count += 1
                        val_str = rule_v.get('last_checked_on', '')
                        if val_str:
                            try:
                                val_date = datetime.strptime(val_str[:10], "%Y-%m-%d")
                                weeks = (now - val_date).days / 7
                                if weeks > 12:
                                    validation_expired_count += 1
                            except:
                                pass
            except:
                pass
        
        return {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': disabled_rules,
            'avg_score': round(avg_score, 1),
            'min_score': min_score,
            'max_score': max_score,
            'rules_by_space': rules_by_space,
            'validated_count': validated_count,
            'validation_expired_count': validation_expired_count,
            'never_validated_count': total_rules - validated_count,
            'severity_breakdown': severity_breakdown,
            'language_breakdown': language_breakdown,
            'low_quality_count': low_quality_count,
            'high_quality_count': high_quality_count
        }
    except Exception as e:
        log_error(f"Get Rule Health Metrics Failed: {e}")
        return {
            'total_rules': 0, 'enabled_rules': 0, 'disabled_rules': 0,
            'avg_score': 0, 'min_score': 0, 'max_score': 0,
            'rules_by_space': {}, 'validated_count': 0, 'validation_expired_count': 0,
            'never_validated_count': 0, 'severity_breakdown': {}, 'language_breakdown': {},
            'low_quality_count': 0, 'high_quality_count': 0
        }
    finally:
        conn.close()

def get_threat_landscape_metrics():
    """Calculate comprehensive threat landscape metrics.
    
    Returns dict with:
    - total_actors, total_ttps (sum), unique_ttps
    - avg_ttps_per_actor, max_ttps_actor
    - coverage stats: covered_ttps, uncovered_ttps, global_coverage_pct
    - origin_breakdown: {country: count}
    - fully_covered_actors, partially_covered_actors, uncovered_actors
    - top_uncovered_ttps: list of most common uncovered techniques
    """
    conn = get_connection(read_only=False)
    try:
        try:
            conn.execute("CHECKPOINT")
        except:
            pass
        
        # Get threat actors
        df_actors = conn.execute("SELECT * FROM threat_actors").df()
        
        if df_actors.empty:
            return {
                'total_actors': 0, 'total_ttps': 0, 'unique_ttps': 0,
                'avg_ttps_per_actor': 0, 'max_ttps_actor': ('N/A', 0),
                'covered_ttps': 0, 'uncovered_ttps': 0, 'global_coverage_pct': 0,
                'origin_breakdown': {}, 'fully_covered_actors': 0,
                'partially_covered_actors': 0, 'uncovered_actors': 0,
                'top_uncovered_ttps': [], 'last_sync': 'Never'
            }
        
        # Get covered TTPs from enabled rules
        try:
            covered_result = conn.execute(
                "SELECT DISTINCT unnest(mitre_ids) FROM detection_rules WHERE enabled = 1"
            ).fetchall()
            covered_ttps = {str(row[0]).strip().upper() for row in covered_result if row[0]}
        except:
            covered_ttps = set()
        
        # Basic counts
        total_actors = len(df_actors)
        total_ttps = int(df_actors['ttp_count'].sum()) if 'ttp_count' in df_actors.columns else 0
        
        # Gather all unique TTPs across all actors
        all_ttps = set()
        ttp_frequency = {}  # Track how often each TTP appears
        for ttps_list in df_actors['ttps']:
            if ttps_list is not None and hasattr(ttps_list, '__len__') and len(ttps_list) > 0:
                for t in ttps_list:
                    t_upper = str(t).strip().upper()
                    all_ttps.add(t_upper)
                    ttp_frequency[t_upper] = ttp_frequency.get(t_upper, 0) + 1
        
        unique_ttps = len(all_ttps)
        
        # Coverage stats
        covered_unique = all_ttps.intersection(covered_ttps)
        uncovered_unique = all_ttps - covered_ttps
        covered_count = len(covered_unique)
        uncovered_count = len(uncovered_unique)
        global_coverage_pct = round((covered_count / unique_ttps * 100), 1) if unique_ttps > 0 else 0
        
        # Top uncovered TTPs (most frequently used but not covered)
        uncovered_freq = {t: ttp_frequency[t] for t in uncovered_unique}
        top_uncovered = sorted(uncovered_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        top_uncovered_ttps = [{'ttp': t, 'count': c} for t, c in top_uncovered]
        
        # Actor stats
        avg_ttps = round(total_ttps / total_actors, 1) if total_actors > 0 else 0
        
        # Find actor with most TTPs
        max_actor_row = df_actors.loc[df_actors['ttp_count'].idxmax()] if 'ttp_count' in df_actors.columns and total_actors > 0 else None
        max_ttps_actor = (max_actor_row['name'], int(max_actor_row['ttp_count'])) if max_actor_row is not None else ('N/A', 0)
        
        # Coverage breakdown by actor
        fully_covered = 0
        partially_covered = 0
        uncovered_actors = 0
        
        for ttps_list in df_actors['ttps']:
            if ttps_list is not None and hasattr(ttps_list, '__len__') and len(ttps_list) > 0:
                actor_ttps = {str(t).strip().upper() for t in ttps_list}
                actor_covered = len(actor_ttps.intersection(covered_ttps))
                if actor_covered == len(actor_ttps):
                    fully_covered += 1
                elif actor_covered > 0:
                    partially_covered += 1
                else:
                    uncovered_actors += 1
            else:
                uncovered_actors += 1
        
        # Origin breakdown
        origin_breakdown = {}
        if 'origin' in df_actors.columns:
            origin_counts = df_actors['origin'].value_counts().to_dict()
            origin_breakdown = {str(k): int(v) for k, v in origin_counts.items() if k}
        
        # Last sync time
        try:
            last_updated = df_actors['last_updated'].max()
            last_sync = last_updated.strftime("%Y-%m-%d %H:%M") if pd.notna(last_updated) else "Never"
        except:
            last_sync = "Never"
        
        return {
            'total_actors': total_actors,
            'total_ttps': total_ttps,
            'unique_ttps': unique_ttps,
            'avg_ttps_per_actor': avg_ttps,
            'max_ttps_actor': max_ttps_actor,
            'covered_ttps': covered_count,
            'uncovered_ttps': uncovered_count,
            'global_coverage_pct': global_coverage_pct,
            'origin_breakdown': origin_breakdown,
            'fully_covered_actors': fully_covered,
            'partially_covered_actors': partially_covered,
            'uncovered_actors': uncovered_actors,
            'top_uncovered_ttps': top_uncovered_ttps,
            'last_sync': last_sync
        }
    except Exception as e:
        log_error(f"Get Threat Landscape Metrics Failed: {e}")
        return {
            'total_actors': 0, 'total_ttps': 0, 'unique_ttps': 0,
            'avg_ttps_per_actor': 0, 'max_ttps_actor': ('N/A', 0),
            'covered_ttps': 0, 'uncovered_ttps': 0, 'global_coverage_pct': 0,
            'origin_breakdown': {}, 'fully_covered_actors': 0,
            'partially_covered_actors': 0, 'uncovered_actors': 0,
            'top_uncovered_ttps': [], 'last_sync': 'Never'
        }
    finally:
        conn.close()
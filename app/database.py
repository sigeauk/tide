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
SCHEMA_VERSION = 2  # Increment this when adding migrations


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
            # Add source column if it doesn't exist
            conn.execute("ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS source VARCHAR[]")
            set_schema_version(conn, 2)
            log_info("✅ Migration 2 completed: Added source column to threat_actors")
        except Exception as e:
            log_error(f"Migration 2 failed: {e}")
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
            else:
                df[col] = None
    return df[required_cols]

# --- INGESTION (Worker Only) ---

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

        target_cols = ['name', 'description', 'ttps', 'ttp_count', 'aliases', 'origin', 'source', 'last_updated']  # Added 'source'
        df['last_updated'] = datetime.now()
        df_final = ensure_columns(df, target_cols)
        
        # Ensure source is a list
        df_final.loc[:, 'source'] = df_final['source'].apply(lambda x: [x] if isinstance(x, str) else x)
        
        # Merge sources with existing
        conn_read = get_connection(read_only=True)
        for index, row in df_final.iterrows():
            actor_name = row['name']
            existing = conn_read.execute("SELECT source FROM threat_actors WHERE name = ?", [actor_name]).fetchone()
            if existing and existing[0]:
                current_sources = existing[0]
                new_sources = list(set(current_sources + row['source']))
                df_final.at[index, 'source'] = new_sources
        conn_read.close()
        
        conn.register('df_source', df_final)
        conn.execute("""
            INSERT INTO threat_actors (name, description, ttps, ttp_count, aliases, origin, source, last_updated)
            SELECT name, description, ttps, ttp_count, aliases, origin, source, last_updated FROM df_source
            ON CONFLICT (name) DO UPDATE SET
                ttps = EXCLUDED.ttps,
                ttp_count = EXCLUDED.ttp_count,
                source = EXCLUDED.source,
                last_updated = EXCLUDED.last_updated
        """)
        return len(df)
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

    conn = get_connection(read_only=False)
    try:
        # Clear existing data - use DELETE which is more reliable
        conn.execute("DELETE FROM detection_rules WHERE 1=1")
        conn.execute("CHECKPOINT")
        
        # Insert fresh data
        conn.register('rules_source', df_final)
        conn.execute("INSERT INTO detection_rules SELECT * FROM rules_source")
        
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
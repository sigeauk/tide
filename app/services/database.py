"""
Database service for TIDE - DuckDB operations.
Ported from the original Streamlit database.py to a FastAPI-friendly singleton pattern.
"""

import duckdb
import json
import os
import time
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Set
from contextlib import contextmanager
from threading import Lock

from app.config import get_settings
from app.models.rules import DetectionRule, RuleHealthMetrics, RuleFilters
from app.models.threats import ThreatActor, MITRETechnique, ThreatLandscapeMetrics

import logging

logger = logging.getLogger(__name__)

# Schema version for migrations
SCHEMA_VERSION = 4


class DatabaseService:
    """
    Singleton database service for DuckDB operations.
    Thread-safe with connection pooling and retry logic.
    """
    
    _instance: Optional["DatabaseService"] = None
    _lock: Lock = Lock()
    
    def __new__(cls) -> "DatabaseService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.settings = get_settings()
        self.db_path = self.settings.db_path
        self.trigger_dir = self.settings.trigger_dir
        self.validation_file = self.settings.validation_file
        self._conn_lock = Lock()
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(self.trigger_dir, exist_ok=True)
        
        # Initialize database
        self._init_db()
        self._initialized = True
        logger.info("🦆 DuckDB Service initialized")
    
    @contextmanager
    def get_connection(self, read_only: bool = False, retries: int = 5, delay: float = 0.5):
        """
        Context manager for database connections with retry logic.
        Always use read_only=False for consistent reads in WAL mode.
        """
        conn = None
        attempt = 0
        
        while attempt < retries:
            try:
                with self._conn_lock:
                    conn = duckdb.connect(self.db_path, read_only=False)
                yield conn
                return
            except duckdb.IOException as e:
                if "lock" in str(e).lower():
                    attempt += 1
                    logger.warning(f"⚠️ DB Locked. Retrying ({attempt}/{retries})...")
                    time.sleep(delay)
                else:
                    raise
            except Exception as e:
                logger.error(f"DB Connection failed: {e}")
                raise
            finally:
                if conn:
                    conn.close()
        
        raise duckdb.IOException("Database locked by another process.")
    
    def _get_schema_version(self, conn) -> int:
        """Get current schema version from database."""
        try:
            result = conn.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_name = 'schema_version'
            """).fetchone()
            
            if result:
                version = conn.execute(
                    "SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1"
                ).fetchone()
                return version[0] if version else 0
            return 0
        except:
            return 0
    
    def _set_schema_version(self, conn, version: int):
        """Record schema version in database."""
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP
            )
        """)
        conn.execute("""
            INSERT INTO schema_version (version, applied_at)
            VALUES (?, now())
            ON CONFLICT (version) DO UPDATE SET applied_at = now()
        """, [version])
    
    def _run_migrations(self, conn):
        """Run database migrations."""
        current_version = self._get_schema_version(conn)
        
        if current_version >= SCHEMA_VERSION:
            return
        
        logger.info(f"🔄 Running migrations from v{current_version} to v{SCHEMA_VERSION}...")
        
        # Migration 1: Initial schema
        if current_version < 1:
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
            self._set_schema_version(conn, 1)
            logger.info("✅ Migration 1: Initial schema created")
        
        # Migration 2: Add/fix source column to threat_actors as VARCHAR[]
        if current_version < 2:
            # Check if source column exists and has wrong type
            cols = conn.execute("DESCRIBE threat_actors").fetchall()
            source_col = next((c for c in cols if c[0] == 'source'), None)
            
            if source_col and source_col[1] == 'VARCHAR':
                # Source column exists but has wrong type - need to fix
                logger.info("🔄 Converting source column from VARCHAR to VARCHAR[]...")
                conn.execute("ALTER TABLE threat_actors ADD COLUMN source_new VARCHAR[]")
                conn.execute("""
                    UPDATE threat_actors 
                    SET source_new = CASE 
                        WHEN source IS NOT NULL AND source != '' THEN [source]
                        ELSE []
                    END
                """)
                conn.execute("ALTER TABLE threat_actors DROP COLUMN source")
                conn.execute("ALTER TABLE threat_actors RENAME COLUMN source_new TO source")
            elif source_col is None:
                conn.execute("ALTER TABLE threat_actors ADD COLUMN source VARCHAR[]")
            
            self._set_schema_version(conn, 2)
            logger.info("✅ Migration 2: Source column fixed as VARCHAR[]")
        
        # Migration 3: Composite PK for detection_rules
        if current_version < 3:
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
            self._set_schema_version(conn, 3)
            logger.info("✅ Migration 3: Composite PK for detection_rules")
        
        # Migration 4: App settings table for runtime configuration
        if current_version < 4:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key VARCHAR PRIMARY KEY,
                    value VARCHAR,
                    updated_at TIMESTAMP DEFAULT now()
                )
            """)
            # Insert defaults
            conn.execute("""
                INSERT OR IGNORE INTO app_settings (key, value) VALUES
                    ('rule_log_enabled', 'false'),
                    ('rule_log_path', '/app/data/log/rules'),
                    ('rule_log_schedule', '00:00'),
                    ('rule_log_retention_days', '7')
            """)
            self._set_schema_version(conn, 4)
            logger.info("✅ Migration 4: App settings table created")
        
        logger.info(f"✅ Migrations complete. Schema v{SCHEMA_VERSION}")
    
    def _validate_legacy_tables(self, conn):
        """Validate legacy tables and align schemas non-destructively."""
        # Check for checkedRule table (legacy validation data)
        try:
            tables = conn.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'main'
            """).fetchall()
            table_names = {t[0] for t in tables}
            
            # If checkedRule exists, validate its schema
            if 'checkedRule' in table_names:
                cols = conn.execute("DESCRIBE checkedRule").fetchall()
                col_names = {c[0] for c in cols}
                
                # Expected columns for legacy compatibility
                expected = {'rule_name', 'last_checked_on', 'checked_by'}
                missing = expected - col_names
                
                if missing:
                    logger.warning(f"⚠️ checkedRule missing columns: {missing}")
                    for col in missing:
                        try:
                            if col == 'rule_name':
                                conn.execute("ALTER TABLE checkedRule ADD COLUMN rule_name VARCHAR")
                            elif col == 'last_checked_on':
                                conn.execute("ALTER TABLE checkedRule ADD COLUMN last_checked_on TIMESTAMP")
                            elif col == 'checked_by':
                                conn.execute("ALTER TABLE checkedRule ADD COLUMN checked_by VARCHAR DEFAULT 'unknown'")
                            logger.info(f"✅ Added missing column: {col}")
                        except Exception as e:
                            logger.warning(f"Could not add column {col}: {e}")
                else:
                    logger.info("✅ checkedRule schema validated")
                    
        except Exception as e:
            logger.warning(f"Legacy table validation skipped: {e}")
    
    def _init_db(self):
        """Initialize database and run migrations."""
        with self.get_connection() as conn:
            self._run_migrations(conn)
            self._validate_legacy_tables(conn)
            self._ensure_users_table(conn)
    
    def _ensure_users_table(self, conn):
        """Create users table if it doesn't exist (for standalone auth)."""
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR PRIMARY KEY DEFAULT (uuid()),
                    username VARCHAR UNIQUE NOT NULL,
                    password_hash VARCHAR NOT NULL,
                    role VARCHAR DEFAULT 'analyst',
                    created_at TIMESTAMP DEFAULT now(),
                    last_login TIMESTAMP
                )
            """)
            logger.info("✅ Users table ready")
        except Exception as e:
            logger.warning(f"Could not create users table: {e}")
    
    # --- VALIDATION DATA ---
    
    def _load_validation_data(self) -> Dict[str, Dict[str, str]]:
        """Load validation data from JSON file."""
        if os.path.exists(self.validation_file):
            try:
                with open(self.validation_file, "r") as f:
                    return json.load(f).get("rules", {})
            except:
                return {}
        return {}
    
    def save_validation(self, rule_name: str, user_name: str):
        """Save validation record for a rule."""
        if os.path.exists(self.validation_file):
            with open(self.validation_file, "r") as f:
                try:
                    data = json.load(f)
                except:
                    data = {"rules": {}}
        else:
            data = {"rules": {}}
        
        if "rules" not in data:
            data["rules"] = {}
        
        data["rules"][str(rule_name)] = {
            "last_checked_on": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "checked_by": user_name
        }
        
        with open(self.validation_file, "w") as f:
            json.dump(data, f, indent=4)
    
    # --- RULE OPERATIONS ---
    
    def get_rules(self, filters: RuleFilters) -> Tuple[List[DetectionRule], int, str]:
        """
        Get paginated list of detection rules with filters.
        Returns (rules, total_count, last_sync).
        """
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            # Base query
            query = "SELECT * FROM detection_rules WHERE 1=1"
            params = []
            
            # Apply filters
            if filters.space:
                query += " AND space = ?"
                params.append(filters.space)
            
            if filters.enabled is not None:
                query += " AND enabled = ?"
                params.append(1 if filters.enabled else 0)
            
            if filters.severity:
                query += " AND severity = ?"
                params.append(filters.severity.value)
            
            if filters.min_score is not None:
                query += " AND score >= ?"
                params.append(filters.min_score)
            
            if filters.max_score is not None:
                query += " AND score <= ?"
                params.append(filters.max_score)
            
            # Apply search filter IN SQL (not post-fetch) so pagination works correctly
            if filters.search:
                search_term = f"%{filters.search}%"
                query += """ AND (
                    LOWER(name) LIKE LOWER(?) 
                    OR LOWER(author) LIKE LOWER(?) 
                    OR LOWER(rule_id) LIKE LOWER(?)
                    OR LOWER(array_to_string(mitre_ids, ',')) LIKE LOWER(?)
                )"""
                params.extend([search_term, search_term, search_term, search_term])
            
            # Get total count before pagination
            count_query = query.replace("SELECT *", "SELECT COUNT(*)")
            total = conn.execute(count_query, params).fetchone()[0]
            
            # Check if sorting by validation date (Python-side sort needed)
            is_validation_sort = filters.sort_by in ("validated_asc", "validated_desc")
            
            # Apply sorting (DB-side for DB columns)
            if not is_validation_sort:
                sort_map = {
                    "score_asc": "score ASC",
                    "score_desc": "score DESC",
                    "name_asc": "name ASC",
                    "name_desc": "name DESC",
                }
                order_by = sort_map.get(filters.sort_by, "score ASC")
                query += f" ORDER BY {order_by}"
            
            if is_validation_sort:
                # Fetch ALL matching rows for Python-side sort, then paginate
                df = conn.execute(query, params).df()
            else:
                # Pagination (DB-side)
                offset = (filters.page - 1) * filters.page_size
                query += f" LIMIT {filters.page_size} OFFSET {offset}"
                df = conn.execute(query, params).df()
            
            # Get last sync time
            try:
                last_sync = df['last_updated'].max().strftime("%Y-%m-%d %H:%M") if not df.empty else "Never"
            except:
                last_sync = "Never"
        
        # Convert to models (search already applied in SQL)
        validation_data = self._load_validation_data()
        rules = []
        
        for _, row in df.iterrows():
            rule = self._row_to_rule(row.to_dict(), validation_data)
            rules.append(rule)
        
        # Python-side sort for validation date
        if is_validation_sort:
            reverse = filters.sort_by == "validated_desc"
            rules.sort(
                key=lambda r: r.validation_date or datetime.min,
                reverse=reverse,
            )
            # Manual pagination
            offset = (filters.page - 1) * filters.page_size
            rules = rules[offset:offset + filters.page_size]
        
        return rules, total, last_sync
    
    def get_rule_by_id(self, rule_id: str, space: str = "default") -> Optional[DetectionRule]:
        """Get a single rule by ID and space."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT * FROM detection_rules WHERE rule_id = ? AND space = ?",
                [rule_id, space]
            ).fetchone()
            
            if result:
                columns = [desc[0] for desc in conn.description]
                row = dict(zip(columns, result))
                validation_data = self._load_validation_data()
                return self._row_to_rule(row, validation_data)
        
        return None
    
    def _row_to_rule(self, row: Dict[str, Any], validation_data: Dict) -> DetectionRule:
        """Convert database row to DetectionRule model."""
        # Parse raw_data
        raw_data = row.get('raw_data')
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except:
                raw_data = {}
        
        # Parse mitre_ids
        mitre_ids = row.get('mitre_ids', [])
        if hasattr(mitre_ids, 'tolist'):
            mitre_ids = mitre_ids.tolist()
        elif not isinstance(mitre_ids, list):
            mitre_ids = []
        
        # Get validation info
        rule_name = row.get('name', '')
        val_info = validation_data.get(str(rule_name), {})
        
        validation_date = None
        validated_by = None
        validation_status = "never"
        
        if val_info:
            val_str = val_info.get('last_checked_on', '')
            validated_by = val_info.get('checked_by')
            if val_str:
                try:
                    validation_date = datetime.strptime(val_str[:19], "%Y-%m-%dT%H:%M:%S")
                    weeks = (datetime.now() - validation_date).days / 7
                    validation_status = "expired" if weeks > 12 else "valid"
                except:
                    pass
        
        return DetectionRule(
            rule_id=row.get('rule_id', ''),
            name=rule_name,
            severity=row.get('severity', 'low'),
            author=row.get('author', 'Unknown'),
            enabled=bool(row.get('enabled', 0)),
            space=row.get('space', 'default'),
            score=row.get('score', 0),
            quality_score=row.get('quality_score', 0),
            meta_score=row.get('meta_score', 0),
            score_mapping=row.get('score_mapping', 0),
            score_field_type=row.get('score_field_type', 0),
            score_search_time=row.get('score_search_time', 0),
            score_language=row.get('score_language', 0),
            score_note=row.get('score_note', 0),
            score_override=row.get('score_override', 0),
            score_tactics=row.get('score_tactics', 0),
            score_techniques=row.get('score_techniques', 0),
            score_author=row.get('score_author', 0),
            score_highlights=row.get('score_highlights', 0),
            mitre_ids=mitre_ids,
            last_updated=row.get('last_updated'),
            raw_data=raw_data,
            validation_date=validation_date,
            validated_by=validated_by,
            validation_status=validation_status,
        )
    
    def get_rule_health_metrics(self) -> RuleHealthMetrics:
        """Calculate comprehensive rule health metrics."""
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            df = conn.execute("SELECT * FROM detection_rules").df()
            
            if df.empty:
                return RuleHealthMetrics()
            
            # Basic counts
            total_rules = len(df)
            enabled_rules = len(df[df['enabled'] == 1])
            
            # Score stats
            avg_score = float(df['score'].mean()) if 'score' in df.columns else 0
            min_score = int(df['score'].min()) if 'score' in df.columns else 0
            max_score = int(df['score'].max()) if 'score' in df.columns else 0
            
            # Quality tiers
            low_quality_count = len(df[df['score'] < 50])
            high_quality_count = len(df[df['score'] >= 80])
            
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
            
            # Language breakdown
            language_breakdown = {}
            if 'raw_data' in df.columns:
                try:
                    langs = df['raw_data'].apply(
                        lambda x: json.loads(x).get('language', 'unknown') if x else 'unknown'
                    )
                    lang_counts = langs.value_counts().to_dict()
                    language_breakdown = {str(k): int(v) for k, v in lang_counts.items()}
                except:
                    pass
        
        # Validation stats (from JSON file)
        validated_count = 0
        validation_expired_count = 0
        validation_data = self._load_validation_data()
        
        if validation_data:
            now = datetime.now()
            for rule_name in df['name'].tolist():
                rule_v = validation_data.get(str(rule_name), {})
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
        
        return RuleHealthMetrics(
            total_rules=total_rules,
            enabled_rules=enabled_rules,
            disabled_rules=total_rules - enabled_rules,
            avg_score=round(avg_score, 1),
            min_score=min_score,
            max_score=max_score,
            validated_count=validated_count,
            validation_expired_count=validation_expired_count,
            never_validated_count=total_rules - validated_count,
            low_quality_count=low_quality_count,
            high_quality_count=high_quality_count,
            rules_by_space=rules_by_space,
            severity_breakdown=severity_breakdown,
            language_breakdown=language_breakdown,
        )
    
    def get_unique_spaces(self) -> List[str]:
        """Get list of unique Kibana spaces."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT DISTINCT space FROM detection_rules ORDER BY space"
            ).fetchall()
            return [row[0] for row in result if row[0]]
    
    def get_promotion_metrics(self) -> Dict[str, Any]:
        """Get metrics specifically for staging rules ready for promotion."""
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            # Get staging rules
            staging_df = conn.execute(
                "SELECT * FROM detection_rules WHERE LOWER(space) = 'staging'"
            ).df()
            
            # Get production rules count
            prod_result = conn.execute(
                "SELECT COUNT(*) FROM detection_rules WHERE LOWER(space) = 'production'"
            ).fetchone()
            production_total = prod_result[0] if prod_result else 0
            
            if staging_df.empty:
                return {
                    'staging_total': 0,
                    'staging_enabled': 0,
                    'staging_avg_score': 0,
                    'staging_min_score': 0,
                    'staging_max_score': 0,
                    'staging_low_quality': 0,
                    'staging_high_quality': 0,
                    'staging_severity': {},
                    'production_total': production_total,
                    'last_sync_status': 'pending',
                    'last_sync_time': 'No staging rules',
                }
            
            staging_total = len(staging_df)
            staging_enabled = len(staging_df[staging_df['enabled'] == 1])
            staging_avg_score = float(staging_df['score'].mean()) if 'score' in staging_df.columns else 0
            staging_min_score = int(staging_df['score'].min()) if 'score' in staging_df.columns else 0
            staging_max_score = int(staging_df['score'].max()) if 'score' in staging_df.columns else 0
            staging_low_quality = len(staging_df[staging_df['score'] < 50])
            staging_high_quality = len(staging_df[staging_df['score'] >= 80])
            
            staging_severity = {}
            if 'severity' in staging_df.columns:
                sev_counts = staging_df['severity'].value_counts().to_dict()
                staging_severity = {str(k).lower(): int(v) for k, v in sev_counts.items()}
            
            return {
                'staging_total': staging_total,
                'staging_enabled': staging_enabled,
                'staging_avg_score': staging_avg_score,
                'staging_min_score': staging_min_score,
                'staging_max_score': staging_max_score,
                'staging_low_quality': staging_low_quality,
                'staging_high_quality': staging_high_quality,
                'staging_severity': staging_severity,
                'production_total': production_total,
                'last_sync_status': 'success',  # TODO: Track actual sync status
                'last_sync_time': 'Ready',
            }
    
    # --- THREAT ACTOR OPERATIONS ---
    
    def get_threat_actors(self) -> List[ThreatActor]:
        """Get all threat actors ordered by TTP count."""
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            df = conn.execute(
                "SELECT * FROM threat_actors ORDER BY ttp_count DESC"
            ).df()
            
            actors = []
            for _, row in df.iterrows():
                ttps = row.get('ttps', [])
                if hasattr(ttps, 'tolist'):
                    ttps = ttps.tolist()
                
                source = row.get('source', [])
                if hasattr(source, 'tolist'):
                    source = source.tolist()
                
                # Handle NaN values for optional string fields
                import math
                origin_val = row.get('origin')
                if origin_val is None or (isinstance(origin_val, float) and math.isnan(origin_val)):
                    origin_val = None
                    
                description_val = row.get('description')
                if description_val is None or (isinstance(description_val, float) and math.isnan(description_val)):
                    description_val = None
                    
                aliases_val = row.get('aliases')
                if aliases_val is None or (isinstance(aliases_val, float) and math.isnan(aliases_val)):
                    aliases_val = None
                
                actors.append(ThreatActor(
                    name=row.get('name', ''),
                    description=description_val,
                    ttps=ttps,
                    ttp_count=row.get('ttp_count', 0),
                    aliases=aliases_val,
                    origin=origin_val,
                    source=source if isinstance(source, list) else [],
                    last_updated=row.get('last_updated'),
                ))
            
            return actors
    
    def get_covered_ttps_by_space(self, space: str = "production") -> Set[str]:
        """Get TTPs covered by enabled detection rules in a specific space."""
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            result = conn.execute("""
                SELECT DISTINCT unnest(mitre_ids) 
                FROM detection_rules 
                WHERE enabled = 1 AND LOWER(space) = LOWER(?)
            """, [space]).fetchall()
            return {row[0].upper() for row in result if row[0]}
    
    def get_technique_rule_counts(self, space: str = "production") -> dict:
        """Get count of enabled rules per MITRE technique in a specific space."""
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            try:
                # Use CTE to unnest first, then group
                result = conn.execute("""
                    WITH unnested AS (
                        SELECT UPPER(unnest(mitre_ids)) as technique
                        FROM detection_rules 
                        WHERE enabled = 1 AND LOWER(space) = LOWER(?)
                    )
                    SELECT technique, COUNT(*) as rule_count
                    FROM unnested
                    WHERE technique IS NOT NULL
                    GROUP BY technique
                """, [space]).fetchall()
                return {row[0]: row[1] for row in result if row[0]}
            except Exception as e:
                logger.warning(f"Failed to get technique rule counts: {e}")
                return {}
    
    def get_threat_landscape_metrics(self) -> "ThreatLandscapeMetrics":
        """Calculate comprehensive threat landscape metrics."""
        from app.models.threats import ThreatLandscapeMetrics
        
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            df = conn.execute("SELECT * FROM threat_actors").df()
            
            if df.empty:
                return ThreatLandscapeMetrics()
            
            # Get covered TTPs from enabled rules in production
            covered_ttps = self.get_covered_ttps_by_space("production")
            
            # Basic counts
            total_actors = len(df)
            total_ttps = int(df['ttp_count'].sum()) if 'ttp_count' in df.columns else 0
            
            # Gather all unique TTPs across all actors
            all_ttps = set()
            for ttps_list in df['ttps']:
                if ttps_list is not None and hasattr(ttps_list, '__len__') and len(ttps_list) > 0:
                    for t in ttps_list:
                        all_ttps.add(str(t).strip().upper())
            
            unique_ttps = len(all_ttps)
            
            # Coverage stats
            covered_unique = all_ttps.intersection(covered_ttps)
            uncovered_unique = all_ttps - covered_ttps
            covered_count = len(covered_unique)
            uncovered_count = len(uncovered_unique)
            global_coverage_pct = round((covered_count / unique_ttps * 100), 1) if unique_ttps > 0 else 0
            
            # Actor stats
            avg_ttps = round(total_ttps / total_actors, 1) if total_actors > 0 else 0
            
            # Origin breakdown
            origin_breakdown = {}
            if 'origin' in df.columns:
                origin_counts = df['origin'].value_counts().to_dict()
                origin_breakdown = {str(k): int(v) for k, v in origin_counts.items() if k}
            
            # Source breakdown
            source_breakdown = {}
            if 'source' in df.columns:
                for source_list in df['source']:
                    if source_list is not None:
                        if hasattr(source_list, 'tolist'):
                            source_list = source_list.tolist()
                        if isinstance(source_list, list):
                            for src in source_list:
                                source_breakdown[src] = source_breakdown.get(src, 0) + 1
            
            # Actor coverage tiers
            fully_covered = 0
            partially_covered = 0
            uncovered_actors = 0
            
            for ttps_list in df['ttps']:
                if ttps_list is None or len(ttps_list) == 0:
                    uncovered_actors += 1
                    continue
                
                actor_ttps = {str(t).strip().upper() for t in ttps_list}
                actor_covered = actor_ttps.intersection(covered_ttps)
                
                if len(actor_covered) == len(actor_ttps):
                    fully_covered += 1
                elif len(actor_covered) > 0:
                    partially_covered += 1
                else:
                    uncovered_actors += 1
            
            return ThreatLandscapeMetrics(
                total_actors=total_actors,
                total_ttps=total_ttps,
                unique_ttps=unique_ttps,
                avg_ttps_per_actor=avg_ttps,
                covered_ttps=covered_count,
                uncovered_ttps=uncovered_count,
                global_coverage_pct=global_coverage_pct,
                origin_breakdown=origin_breakdown,
                source_breakdown=source_breakdown,
                fully_covered_actors=fully_covered,
                partially_covered_actors=partially_covered,
                uncovered_actors=uncovered_actors,
            )
    
    def get_all_covered_ttps(self) -> Set[str]:
        """Get all TTPs covered by enabled detection rules."""
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            result = conn.execute(
                "SELECT DISTINCT unnest(mitre_ids) FROM detection_rules WHERE enabled = 1"
            ).fetchall()
            return {row[0].upper() for row in result if row[0]}
    
    def get_ttp_rule_counts(self) -> Dict[str, int]:
        """Get count of enabled rules per MITRE technique ID."""
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            result = conn.execute("""
                SELECT ttp_id, COUNT(*) as rule_count
                FROM (
                    SELECT unnest(mitre_ids) as ttp_id
                    FROM detection_rules 
                    WHERE enabled = 1
                )
                GROUP BY ttp_id
            """).fetchall()
            return {row[0].upper(): row[1] for row in result if row[0]}
    
    def get_technique_map(self) -> Dict[str, str]:
        """Get mapping of technique IDs to tactics."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT id, tactic FROM mitre_techniques"
            ).fetchall()
            return {row[0]: row[1] for row in result if row[0] and row[1]}
    
    def get_technique_names(self) -> Dict[str, str]:
        """Get mapping of technique IDs to names."""
        with self.get_connection() as conn:
            result = conn.execute(
                "SELECT id, name FROM mitre_techniques"
            ).fetchall()
            return {row[0]: row[1] for row in result if row[0] and row[1]}
    
    def get_rules_for_technique(self, technique_id: str, enabled_only: bool = True, search: str = None) -> List[DetectionRule]:
        """Get all detection rules that cover a specific MITRE technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., T1059)
            enabled_only: If True, only return enabled rules (default). Matches heatmap coverage logic.
            search: Optional search filter to further restrict rules (matches name, author, rule_id, mitre_ids)
        """
        with self.get_connection() as conn:
            try:
                conn.execute("CHECKPOINT")
            except:
                pass
            
            # Query rules where the technique ID is in the mitre_ids array
            ttp_upper = technique_id.upper()
            
            # Build query with search filter if provided
            base_conditions = "(array_contains(mitre_ids, ?) OR array_contains(mitre_ids, ?))"
            params = [ttp_upper, technique_id]
            
            if enabled_only:
                base_conditions += " AND enabled = 1"
            
            if search:
                # Apply same search logic as grid - match name, author, rule_id, OR mitre_ids
                # This ensures sidebar shows rules from the same result set as the grid
                search_term = f"%{search}%"
                base_conditions += """ AND (
                    LOWER(name) LIKE LOWER(?) 
                    OR LOWER(author) LIKE LOWER(?) 
                    OR LOWER(rule_id) LIKE LOWER(?)
                    OR LOWER(array_to_string(mitre_ids, ',')) LIKE LOWER(?)
                )"""
                params.extend([search_term, search_term, search_term, search_term])
            
            query = f"""
                SELECT * FROM detection_rules 
                WHERE {base_conditions}
                ORDER BY score DESC
            """
            
            result = conn.execute(query, params).fetchall()
            
            if not result:
                return []
            
            columns = [desc[0] for desc in conn.description]
            validation_data = self._load_validation_data()
            rules = []
            
            for row_tuple in result:
                row = dict(zip(columns, row_tuple))
                rules.append(self._row_to_rule(row, validation_data))
            
            return rules
    
    # --- TRIGGERS (for background sync) ---
    
    def set_trigger(self, trigger_name: str):
        """Set a trigger file for the background worker."""
        path = os.path.join(self.trigger_dir, trigger_name)
        with open(path, 'w') as f:
            f.write("1")
    
    def check_and_clear_trigger(self, trigger_name: str) -> bool:
        """Check and clear a trigger file."""
        path = os.path.join(self.trigger_dir, trigger_name)
        if os.path.exists(path):
            try:
                os.remove(path)
                return True
            except:
                pass
        return False
    
    # --- DATA MANAGEMENT ---
    
    # --- APP SETTINGS ---
    
    def get_setting(self, key: str, default: str = None) -> str:
        """Get a single app setting by key."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT value FROM app_settings WHERE key = ?", [key]
            ).fetchone()
            return row[0] if row else default
    
    def get_all_settings(self) -> Dict[str, str]:
        """Get all app settings as a dict."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
            return {r[0]: r[1] for r in rows}
    
    def save_setting(self, key: str, value: str):
        """Save a single app setting (upsert)."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, now())
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = EXCLUDED.updated_at
            """, [key, value])
    
    def save_settings(self, settings_dict: Dict[str, str]):
        """Save multiple settings at once."""
        with self.get_connection() as conn:
            for key, value in settings_dict.items():
                conn.execute("""
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (?, ?, now())
                    ON CONFLICT (key) DO UPDATE SET
                        value = EXCLUDED.value,
                        updated_at = EXCLUDED.updated_at
                """, [key, value])
    
    def get_all_rules_for_export(self) -> List[Dict[str, Any]]:
        """Get all detection rules as dicts for JSON log export."""
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT rule_id, name, severity, author, enabled, space,
                       score, quality_score, meta_score,
                       score_mapping, score_field_type, score_search_time, score_language,
                       score_note, score_override, score_tactics, score_techniques,
                       score_author, score_highlights, mitre_ids
                FROM detection_rules
                ORDER BY name
            """).fetchall()
            
            columns = ['rule_id', 'name', 'severity', 'author', 'enabled', 'space',
                       'score', 'quality_score', 'meta_score',
                       'score_mapping', 'score_field_type', 'score_search_time', 'score_language',
                       'score_note', 'score_override', 'score_tactics', 'score_techniques',
                       'score_author', 'score_highlights', 'mitre_ids']
            
            return [dict(zip(columns, row)) for row in rows]
    
    # --- EXISTING DATA MANAGEMENT ---
    
    def clear_detection_rules(self) -> int:
        """Clear all detection rules. Returns count of deleted rows."""
        with self.get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
            conn.execute("DELETE FROM detection_rules WHERE 1=1")
            conn.execute("CHECKPOINT")
            logger.info(f"🗑️ Cleared {count} detection rules")
            return count
    
    def save_audit_results(self, audit_list: List[Dict[str, Any]]) -> int:
        """
        Save detection rules from Elastic sync to database.
        This replaces rules for each synced space to ensure live/accurate data.
        """
        if not audit_list:
            return 0
        
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
        
        # Get unique spaces being synced - we'll delete all rules from these spaces first
        synced_spaces = df['space'].unique().tolist()
        logger.info(f"🔄 Syncing rules for spaces: {synced_spaces}")
        
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
        
        # Ensure all columns exist
        for col in target_cols:
            if col not in df.columns:
                df[col] = None
        
        df_final = df[target_cols].copy()
        
        # Check for duplicates within the incoming data (same rule_id + space)
        duplicates = df_final[df_final.duplicated(subset=['rule_id', 'space'], keep='first')]
        if not duplicates.empty:
            dup_names = duplicates['name'].tolist()
            logger.info(f"⚠️ Skipping {len(dup_names)} duplicate rules (same rule_id + space): {dup_names[:5]}{'...' if len(dup_names) > 5 else ''}")
            df_final = df_final.drop_duplicates(subset=['rule_id', 'space'], keep='first')

        with self.get_connection() as conn:
            try:
                conn.execute("BEGIN TRANSACTION")
                
                # Delete existing rules from synced spaces to ensure live data
                # This ensures removed rules don't persist in the database
                for space in synced_spaces:
                    deleted = conn.execute(
                        "DELETE FROM detection_rules WHERE space = ?",
                        [space]
                    ).fetchone()
                    logger.debug(f"🗑️ Cleared rules from space '{space}'")
                
                # Insert fresh rules
                conn.register('rules_source', df_final)
                conn.execute("""
                    INSERT INTO detection_rules 
                    SELECT * FROM rules_source
                """)
                
                conn.execute("COMMIT")
                
                count = len(df_final)
                logger.info(f"✅ Synced {count} detection rules to database (replaced rules in spaces: {synced_spaces})")
                
            except Exception as e:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                logger.error(f"❌ Failed to save rules: {e}")
                raise
        
        # Checkpoint outside transaction context to avoid concurrency issues
        try:
            with self.get_connection() as conn:
                conn.execute("CHECKPOINT")
        except Exception:
            pass  # Auto-checkpoint will handle it
        
        return count


# Singleton accessor
def get_database_service() -> DatabaseService:
    """Get the database service singleton."""
    return DatabaseService()

"""
VeriPipe AST SQL Validator
Author: Avon Budhathoki
"""

from typing import Dict, Any, List, Set, Optional
import sqlglot
from sqlglot import exp

class SQLFirewall:
    def __init__(self, allowed_tables: Optional[Set[str]] = None, max_limit: int = 1000):
        self.allowed_tables = {t.lower() for t in allowed_tables} if allowed_tables else None
        self.max_limit = max_limit

    def validate_query(self, sql: str) -> Dict[str, Any]:
        """Parse SQL and verify schema integrity and security safety rules."""
        try:
            parsed = sqlglot.parse_one(sql)
        except Exception as e:
            return {
                "valid": False,
                "error": f"SQL Syntax Error: {str(e)}",
                "risk_level": "HIGH"
            }

        # Check query type (only allow SELECT for agent safety)
        if not isinstance(parsed, exp.Select):
            return {
                "valid": False,
                "error": f"Security Violation: Only SELECT queries are permitted (got {parsed.key.upper()}).",
                "risk_level": "CRITICAL"
            }

        # Extract tables referenced in query
        tables_found = set()
        for table in parsed.find_all(exp.Table):
            tables_found.add(table.name.lower())

        if self.allowed_tables is not None:
            unauthorized = tables_found - self.allowed_tables
            if unauthorized:
                return {
                    "valid": False,
                    "error": f"Schema Violation: Tables not found in schema whitelist: {list(unauthorized)}",
                    "risk_level": "HIGH"
                }

        # Enforce LIMIT
        limit_exp = parsed.find(exp.Limit)
        if not limit_exp:
            # Auto-rewrite to inject limit safely
            parsed = parsed.limit(self.max_limit)
            modified_sql = parsed.sql()
            note = f"Auto-injected LIMIT {self.max_limit}"
        else:
            modified_sql = parsed.sql()
            note = "Query includes explicit LIMIT"

        return {
            "valid": True,
            "original_sql": sql,
            "executable_sql": modified_sql,
            "tables_accessed": list(tables_found),
            "note": note,
            "risk_level": "LOW"
        }

#!/usr/bin/env python3
"""
CTF Mode — Scan Agent Fase 7.4
================================
Motor de gamificación para clases de seguridad. Carga desafíos desde
config/ctf_challenges.json y permite a los estudiantes completar retos
usando los resultados del escáner.

Flujo:
  1. ctf = CTFEngine(student_id="estudiante_01")
  2. ctf.list_challenges()
  3. ctf.start_challenge("CTF-01")
  4. # ejecutar escaneo...
  5. resultado = ctf.submit(challenge_id, vulnerabilities)
  6. ctf.scoreboard()
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("scan_agent.ctf")

_DIFFICULTY_EMOJI = {"facil": "🟢", "medio": "🟡", "dificil": "🔴"}
_SEV_COLOR = {"critica": "\033[91m", "alta": "\033[93m", "media": "\033[94m"}
_RESET = "\033[0m"


class CTFEngine:
    """Motor de desafíos CTF para estudiantes."""

    DEFAULT_CONFIG = Path(__file__).parent.parent.parent / "config" / "ctf_challenges.json"
    DEFAULT_DB = Path(__file__).parent.parent.parent / "data" / "ctf_progress.db"

    def __init__(
        self,
        student_id: str = "",
        config_path: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        self.student_id = student_id or os.environ.get("STUDENT_ID", "anonymous")
        cfg_file = Path(config_path) if config_path else self.DEFAULT_CONFIG
        self.config = self._load_config(cfg_file)
        self.challenges: Dict[str, Dict] = {
            c["id"]: c for c in self.config.get("challenges", [])
        }
        self.db_path = Path(db_path) if db_path else self.DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_challenges(self, show_completed: bool = True) -> None:
        """Imprime la lista de desafíos con estado y puntuación."""
        completed = self._get_completed_ids()
        print(f"\n{'='*70}")
        print(f" CTF — {self.config.get('title', 'Desafíos')}")
        print(f" Estudiante: {self.student_id}  |  Score: {self.total_score()} pts")
        print(f"{'='*70}")
        for cid, ch in self.challenges.items():
            done = "✅" if cid in completed else "⬜"
            diff = _DIFFICULTY_EMOJI.get(ch.get("difficulty", ""), "⚪")
            pts = ch.get("points", 0)
            if cid in completed:
                entry = self._get_submission(cid)
                pts_earned = entry.get("points_earned", 0) if entry else 0
                print(f"  {done} {diff} [{cid}] {ch['title']:<40} {pts_earned}/{pts} pts")
            else:
                print(f"  {done} {diff} [{cid}] {ch['title']:<40} {pts} pts")
        print(f"{'='*70}\n")

    def start_challenge(self, challenge_id: str) -> Optional[Dict]:
        """Inicia el temporizador para un desafío. Devuelve el desafío o None."""
        ch = self.challenges.get(challenge_id)
        if not ch:
            print(f"[CTF] Desafío '{challenge_id}' no encontrado.")
            return None
        self._record_start(challenge_id)
        print(f"\n{'='*60}")
        print(f" 🏁 Iniciando: [{challenge_id}] {ch['title']}")
        print(f" Categoría: {ch['category']}  |  {ch['owasp']}")
        print(f" Dificultad: {_DIFFICULTY_EMOJI.get(ch['difficulty'],'')} {ch['difficulty']}")
        print(f" Puntos base: {ch['points']}")
        print(f"\n {ch['description']}")
        target_key = ch.get("target", "")
        target_url = self.config.get("targets", {}).get(target_key, target_key)
        if target_url:
            print(f"\n 🎯 Objetivo: {target_url}")
        print(f"\n 🎓 Objetivo educativo: {ch.get('learning_objective', '')}")
        print(f"{'='*60}\n")
        return ch

    def hint(self, challenge_id: str) -> Optional[str]:
        """Muestra la pista del desafío y aplica penalización de puntos."""
        ch = self.challenges.get(challenge_id)
        if not ch:
            return None
        penalty = ch.get("hint_penalty", 0)
        self._record_hint_used(challenge_id, penalty)
        tip = ch.get("hint", "Sin pista disponible.")
        print(f"\n💡 Pista [{challenge_id}]: {tip}")
        if penalty:
            print(f"   ⚠️  Penalización aplicada: -{penalty} pts")
        return tip

    def submit(self, challenge_id: str, vulnerabilities: List[Dict]) -> Dict:
        """Evalúa si las vulnerabilidades encontradas completan el desafío."""
        ch = self.challenges.get(challenge_id)
        if not ch:
            return {"success": False, "message": f"Desafío '{challenge_id}' no encontrado"}

        if challenge_id in self._get_completed_ids():
            return {"success": False, "message": "Este desafío ya fue completado"}

        validation = ch.get("validation", {})
        matched, count = self._validate(validation, vulnerabilities)

        if not matched:
            needed = validation.get("min_count", 1)
            return {
                "success": False,
                "message": f"No se encontraron suficientes hallazgos (encontrados: {count}, necesarios: {needed})",
                "found": count,
            }

        elapsed = self._elapsed_seconds(challenge_id)
        base_pts = ch.get("points", 100)
        hint_pen = self._hint_penalty(challenge_id)
        time_bonus = self._calc_time_bonus(elapsed, base_pts)
        total = max(0, base_pts - hint_pen + time_bonus)

        self._record_completion(challenge_id, total, elapsed, count)

        result = {
            "success": True,
            "challenge_id": challenge_id,
            "title": ch["title"],
            "points_base": base_pts,
            "hint_penalty": hint_pen,
            "time_bonus": time_bonus,
            "points_earned": total,
            "elapsed_seconds": elapsed,
            "findings_matched": count,
        }
        self._print_success(result, ch)
        return result

    def scoreboard(self) -> List[Dict]:
        """Muestra el scoreboard global de todos los estudiantes."""
        rows = self._db_scoreboard()
        print(f"\n{'='*55}")
        print(f" 🏆 SCOREBOARD — {self.config.get('title', 'CTF')}")
        print(f"{'='*55}")
        for i, row in enumerate(rows[:20], 1):
            marker = " ← tú" if row["student_id"] == self.student_id else ""
            print(f"  {i:2}. {row['student_id']:<25} {row['total_score']:>6} pts{marker}")
        print(f"{'='*55}\n")
        return rows

    def total_score(self) -> int:
        return self._db_student_score(self.student_id)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, validation: Dict, vulns: List[Dict]) -> Tuple[bool, int]:
        vtype = validation.get("type", "vulnerability_found")
        if vtype != "vulnerability_found":
            return False, 0

        tipo_matches = validation.get("tipo_matches", [])
        min_count = validation.get("min_count", 1)

        count = 0
        for v in vulns:
            tipo = v.get("tipo", "")
            owasp_web = v.get("owasp_category", "")
            owasp_api = v.get("owasp_api_category", "")
            fields = [tipo, owasp_web, owasp_api]
            for tm in tipo_matches:
                if any(tm.lower() in f.lower() for f in fields if f):
                    count += 1
                    break

        return count >= min_count, count

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _calc_time_bonus(self, elapsed_sec: int, base_pts: int) -> int:
        scoring = self.config.get("scoring", {}).get("time_bonus", {})
        if not scoring.get("enabled", False):
            return 0
        max_pct = scoring.get("max_bonus_pct", 50) / 100
        full_min = scoring.get("full_bonus_minutes", 10) * 60
        zero_min = scoring.get("zero_bonus_minutes", 60) * 60
        if elapsed_sec <= full_min:
            pct = max_pct
        elif elapsed_sec >= zero_min:
            pct = 0.0
        else:
            pct = max_pct * (1 - (elapsed_sec - full_min) / (zero_min - full_min))
        return int(base_pts * pct)

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS ctf_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    points_earned INTEGER DEFAULT 0,
                    hint_used INTEGER DEFAULT 0,
                    hint_penalty INTEGER DEFAULT 0,
                    elapsed_seconds INTEGER DEFAULT 0,
                    findings_matched INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS ctf_hints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    penalty INTEGER DEFAULT 0,
                    used_at TEXT
                );
            """)

    def _record_start(self, cid: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO ctf_attempts (student_id, challenge_id, started_at) VALUES (?,?,?)",
                (self.student_id, cid, datetime.now(timezone.utc).isoformat()),
            )

    def _record_hint_used(self, cid: str, penalty: int) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO ctf_hints (student_id, challenge_id, penalty, used_at) VALUES (?,?,?,?)",
                (self.student_id, cid, penalty, datetime.now(timezone.utc).isoformat()),
            )

    def _record_completion(self, cid: str, pts: int, elapsed: int, matched: int) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """UPDATE ctf_attempts
                   SET completed_at=?, points_earned=?, elapsed_seconds=?, findings_matched=?
                   WHERE student_id=? AND challenge_id=? AND completed_at IS NULL""",
                (datetime.now(timezone.utc).isoformat(), pts, elapsed, matched,
                 self.student_id, cid),
            )

    def _get_completed_ids(self) -> set:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT challenge_id FROM ctf_attempts WHERE student_id=? AND completed_at IS NOT NULL",
                (self.student_id,),
            ).fetchall()
        return {r[0] for r in rows}

    def _get_submission(self, cid: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT points_earned, elapsed_seconds FROM ctf_attempts WHERE student_id=? AND challenge_id=? AND completed_at IS NOT NULL",
                (self.student_id, cid),
            ).fetchone()
        if row:
            return {"points_earned": row[0], "elapsed_seconds": row[1]}
        return None

    def _elapsed_seconds(self, cid: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT started_at FROM ctf_attempts WHERE student_id=? AND challenge_id=?",
                (self.student_id, cid),
            ).fetchone()
        if not row or not row[0]:
            return 9999
        started = datetime.fromisoformat(row[0])
        return int((datetime.now(timezone.utc) - started).total_seconds())

    def _hint_penalty(self, cid: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(penalty),0) FROM ctf_hints WHERE student_id=? AND challenge_id=?",
                (self.student_id, cid),
            ).fetchone()
        return row[0] if row else 0

    def _db_scoreboard(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT student_id, SUM(points_earned) as total_score
                   FROM ctf_attempts WHERE completed_at IS NOT NULL
                   GROUP BY student_id ORDER BY total_score DESC""",
            ).fetchall()
        return [{"student_id": r[0], "total_score": r[1]} for r in rows]

    def _db_student_score(self, student_id: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(points_earned),0) FROM ctf_attempts WHERE student_id=? AND completed_at IS NOT NULL",
                (student_id,),
            ).fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Config loader
    # ------------------------------------------------------------------

    def _load_config(self, cfg_file: Path) -> Dict:
        if cfg_file.exists():
            return json.loads(cfg_file.read_text(encoding="utf-8"))
        logger.warning("CTF config no encontrado en %s", cfg_file)
        return {"challenges": [], "targets": {}, "scoring": {}}

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def _print_success(self, result: Dict, ch: Dict) -> None:
        print(f"\n{'='*60}")
        print(f" 🎉 ¡DESAFÍO COMPLETADO! [{result['challenge_id']}] {result['title']}")
        print(f"{'='*60}")
        print(f" Puntos base:       {result['points_base']:>6}")
        if result["hint_penalty"]:
            print(f" Penalización pista:{result['hint_penalty']:>6} pts")
        if result["time_bonus"]:
            print(f" Bonus tiempo:      +{result['time_bonus']:>5} pts")
        print(f" {'─'*30}")
        print(f" TOTAL:             {result['points_earned']:>6} pts")
        print(f"\n 🎓 {ch.get('learning_objective', '')}")
        print(f"{'='*60}\n")

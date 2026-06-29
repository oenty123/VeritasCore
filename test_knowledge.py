"""Tests for cross-project learning (knowledge.py)."""
import unittest
import veritas_knowledge as kb


def policy(sink, guard, conf=1.0, count=10):
    return {sink: {"guard": guard, "confidence": conf, "count": count}}


class AllowlistGate(unittest.TestCase):
    def test_unsafe_guard_rejected_even_if_taught(self):
        # subprocess.run -> str must never be learned, no matter how many projects
        db = {"version": 1, "projects": {}}
        for i in range(50):
            kb.learn_project(db, f"p{i}", policy("subprocess.run", "str"))
        self.assertEqual(kb.ecosystem_contracts(db), {})

    def test_real_sanitizer_is_learnable(self):
        db = {"version": 1, "projects": {}}
        for i in range(3):
            kb.learn_project(db, f"p{i}", policy("subprocess.run", "shlex.quote"))
        eco = kb.ecosystem_contracts(db)
        self.assertIn("subprocess.run", eco)
        self.assertEqual(eco["subprocess.run"]["guard"], "shlex.quote")

    def test_structural_parameterized_allowed(self):
        db = {"version": 1, "projects": {}}
        for i in range(3):
            kb.learn_project(db, f"p{i}", policy("sqlite3.execute", "parameterized"))
        self.assertIn("sqlite3.execute", kb.ecosystem_contracts(db))


class ThreeFilters(unittest.TestCase):
    def test_single_project_stays_quarantine(self):
        db = {"version": 1, "projects": {}}
        kb.learn_project(db, "only", policy("subprocess.run", "shlex.quote"))
        agg = kb.aggregate(db)
        self.assertEqual(agg["subprocess.run"]["status"], "quarantine")
        self.assertEqual(kb.ecosystem_contracts(db), {})

    def test_three_consistent_projects_activate(self):
        db = {"version": 1, "projects": {}}
        for i in range(3):
            kb.learn_project(db, f"p{i}", policy("subprocess.run", "shlex.quote"))
        self.assertEqual(kb.aggregate(db)["subprocess.run"]["status"], "active")

    def test_low_consensus_stays_quarantine(self):
        # 2 projects say shlex.quote, 2 say shlex.split -> consensus 0.5 < 0.6
        db = {"version": 1, "projects": {}}
        kb.learn_project(db, "a", policy("subprocess.run", "shlex.quote"))
        kb.learn_project(db, "b", policy("subprocess.run", "shlex.quote"))
        kb.learn_project(db, "c", policy("subprocess.run", "shlex.split"))
        kb.learn_project(db, "d", policy("subprocess.run", "shlex.split"))
        self.assertEqual(kb.aggregate(db)["subprocess.run"]["status"], "quarantine")


class Provenance(unittest.TestCase):
    def test_forget_project_rolls_back(self):
        db = {"version": 1, "projects": {}}
        for i in range(3):
            kb.learn_project(db, f"p{i}", policy("subprocess.run", "shlex.quote"))
        self.assertIn("subprocess.run", kb.ecosystem_contracts(db))
        kb.forget_project(db, "p0")
        # now only 2 projects -> drops below MIN_PROJECTS -> quarantine
        self.assertEqual(kb.ecosystem_contracts(db), {})

    def test_contracts_carry_provenance(self):
        db = {"version": 1, "projects": {}}
        for n in ("flask", "django", "fastapi"):
            kb.learn_project(db, n, policy("sqlite3.execute", "parameterized"))
        c = kb.aggregate(db)["sqlite3.execute"]
        self.assertEqual(c["projects"], ["django", "fastapi", "flask"])
        self.assertEqual(c["n_projects"], 3)


class AntiContracts(unittest.TestCase):
    def test_deviation_from_ecosystem_flagged(self):
        db = {"version": 1, "projects": {}}
        for i in range(3):
            kb.learn_project(db, f"p{i}", policy("subprocess.run", "shlex.quote"))
        # a project that does NOT use the ecosystem guard
        proj = {"subprocess.run": {"guard": None, "confidence": 0.0, "count": 0}}
        flags = kb.anti_contracts(db, proj)
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["ecosystem_guard"], "shlex.quote")

    def test_conforming_project_not_flagged(self):
        db = {"version": 1, "projects": {}}
        for i in range(3):
            kb.learn_project(db, f"p{i}", policy("subprocess.run", "shlex.quote"))
        proj = policy("subprocess.run", "shlex.quote")
        self.assertEqual(kb.anti_contracts(db, proj), [])

    def test_quarantine_does_not_drive_anti_contracts(self):
        # only 1 project -> quarantine -> no anti-contract pressure yet
        db = {"version": 1, "projects": {}}
        kb.learn_project(db, "a", policy("subprocess.run", "shlex.quote"))
        proj = {"subprocess.run": {"guard": None, "count": 0}}
        self.assertEqual(kb.anti_contracts(db, proj), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

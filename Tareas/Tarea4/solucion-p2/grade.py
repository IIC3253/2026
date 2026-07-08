import os
import sys
import json
import subprocess
import shutil
from collections import defaultdict

STUDENT_FILE = 'pregunta2.py'  # <-- cambia esto por el nombre de tu archivo
TEST_FILE = 'test_pregunta2.py'
REF_FILE = 'reference_pregunta2.py'
IMPORT_MODULE = 'student_pregunta2.py'
REPORT_JSON = '.report.json'
PER_TEST_TIMEOUT = 5

# Peso de rúbrica (en puntos, de 2.0) para el nombre base de cada test.
WEIGHTS = {
    "test_init_p_not_prime": 0.25,
    "test_init_q_not_prime": 0.25,
    "test_init_g_wrong_order": 0.25,
    "test_verifier_g_wrong_order": 0.25,
    "test_valid_signature": 0.5,
    "test_linkability": 0.25,
    "test_tampered_signature": 0.25,
}


def main():
    if not os.path.isfile(STUDENT_FILE):
        print(f"no existe el archivo: {STUDENT_FILE}")
        sys.exit(1)

    shutil.copy(STUDENT_FILE, IMPORT_MODULE)

    res = subprocess.run(
        ["python", "-m", "pytest", TEST_FILE,
         "--json-report", f"--json-report-file={REPORT_JSON}",
         "-q", "--tb=short", "-p", "no:randomly",
         "--timeout", str(PER_TEST_TIMEOUT), "--timeout-method", "signal"],
        capture_output=True, text=True,
    )

    if not os.path.exists(REPORT_JSON):
        print("CRASH: pytest no generó reporte (error de import/colección).")
        print(res.stdout)
        print(res.stderr)
        sys.exit(1)

    with open(REPORT_JSON) as f:
        report = json.load(f)

    # Agrupa por ítem de rúbrica (nombre base), sumando todas las parametrizaciones.
    groups = defaultdict(lambda: {"passed": 0, "total": 0})
    for test in report.get("tests", []):
        base = test["nodeid"].split("::")[-1].split("[")[0]
        groups[base]["total"] += 1
        if test["outcome"] == "passed":
            groups[base]["passed"] += 1

    grade = 0.0
    for base, weight in WEIGHTS.items():
        stats = groups.get(base)
        if not stats or not stats["total"]:
            print(f"  {base:28s} SIN RECOLECTAR")
            continue
        frac = stats["passed"] / stats["total"]
        pts = weight * frac
        grade += pts
        flag = "OK " if stats["passed"] == stats["total"] else "!! "
        print(f"  {flag}{base:28s} {stats['passed']:2d}/{stats['total']:<2d}  +{pts:.2f}")

    print(f"\nNota (0-2): {round(grade, 2)}")


if __name__ == "__main__":
    main()

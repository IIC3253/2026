import os
import json
import subprocess
from collections import defaultdict

TEST_FILE = 'test_feistel.py'
REF_FILE = 'reference_feistel.py'
REPORT_JSON = 'out.report.json'

def get_base_score(base_name):
    if 'cbc' in base_name.lower():
        return 0.45
    return 0.15

def grade_user():
    subprocess.run(
        ["python", "-m", "pytest", TEST_FILE, "--json-report", f"--json-report-file={REPORT_JSON}"],
        capture_output=True
    )

    if not os.path.exists(REPORT_JSON):
        return 1.0, "Pytest crash"

    with open(REPORT_JSON, 'r') as f:
        report = json.load(f)
    
    groups = defaultdict(lambda: defaultdict(lambda: {"passed": 0, "total": 0}))
    failed_names = set()
    
    for test in report.get("tests", []):
        nodeid = test["nodeid"] # test_feistel.py::test_enc_block_ok[SHA256-msg_factory0]
        name_part = nodeid.split("::")[-1]
        base_name = name_part.split("[")[0]
        config = name_part.split("[")[1].split("-")[0] # SHA256 or SHA512
        
        groups[config][base_name]["total"] += 1
        if test["outcome"] == "passed":
            groups[config][base_name]["passed"] += 1
        else:
            failed_names.add(f"{base_name}[{config}]")

    total_score = 1.0
    for config, base_tests in groups.items():
        for base_name, stats in base_tests.items():
            max_score = get_base_score(base_name)
            fraction = stats["passed"] / stats["total"]
            total_score += max_score * fraction

    total_score = round(total_score, 2)
    print(f"  -> Nota: {total_score}")
    
    if len(failed_names) == 0:
        comment = "Todo OK"
    else:
        comment = "Fallaron: " + ", ".join(failed_names)

    return total_score, comment

if __name__ == "__main__":
    grade_user()

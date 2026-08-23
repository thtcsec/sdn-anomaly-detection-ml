# Pack a lean review bundle for an external AI (not the whole repo).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\pack_review_for_ai.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\pack_review_for_ai.ps1 -CopyToDesktop
#   powershell -ExecutionPolicy Bypass -File scripts\pack_review_for_ai.ps1 -OutZip "$env:USERPROFILE\Desktop\sdn_ml_review_pack.zip"
#
# Default zip: <repo>\tmp\sdn_ml_review_pack.zip  (gitignored). Do not commit the zip.

[CmdletBinding()]
param(
    [string]$OutZip = "",
    [switch]$CopyToDesktop
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
$GitSha = "unknown"
try {
    $sha = git -C $Root rev-parse --short HEAD 2>$null
    if ($sha) { $GitSha = "$sha".Trim() }
} catch { }

$TmpDir = Join-Path $Root "tmp"
$Staging = Join-Path $TmpDir "sdn_ml_review_pack_staging"
if (-not $OutZip) {
    $OutZip = Join-Path $TmpDir "sdn_ml_review_pack.zip"
}

New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
if (Test-Path -LiteralPath $Staging) {
    Remove-Item -LiteralPath $Staging -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Staging | Out-Null

$Packed = New-Object System.Collections.Generic.List[string]
$Missing = New-Object System.Collections.Generic.List[string]
$SkippedOptional = New-Object System.Collections.Generic.List[string]

function Add-PackFile {
    param(
        [Parameter(Mandatory = $true)][string]$Rel,
        [switch]$Optional
    )
    $src = Join-Path $Root $Rel
    if (-not (Test-Path -LiteralPath $src)) {
        if ($Optional) { [void]$SkippedOptional.Add($Rel) } else { [void]$Missing.Add($Rel) }
        return
    }
    $dst = Join-Path $Staging $Rel
    $dstDir = Split-Path -Parent $dst
    if (-not (Test-Path -LiteralPath $dstDir)) {
        New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    }
    Copy-Item -LiteralPath $src -Destination $dst -Force
    [void]$Packed.Add(($Rel -replace "/", "\"))
}

# Must-have: thesis locks, eval numbers, live path.
$Must = @(
    "README.md"
    "requirements.txt"
    "requirements-dev.txt"
    "start_demo.ps1"
    "start_demo.bat"
    "docs\CAM_NANG_BAO_VE_FULL.md"
    "docs\PROMPT_PHAN_BIEN_AI.md"
    "docs\FAULT_DATASET.md"
    "docs\THESIS_EVALUATION_PROTOCOL.md"
    "docs\DATA_PROVENANCE_SCHEMA.md"
    "src\model_catalog.py"
    "src\mitigation_policy.py"
    "src\realtime_protocol.py"
    "src\eval_binary_realtime_scenario_held_out.py"
    "src\eval_fault_loso.py"
    "src\provenance_schema.py"
    "controller\realtime_detector.py"
    "controller\run_realtime.py"
    "controller\openflow_bind.py"
    "controller\monitor.py"
    "dashboard\app.py"
    "dashboard\templates\index.html"
    "topology\custom_topo.py"
    "dataset\controller_config.json"
    "reports\binary_realtime_loso_summary.csv"
    "reports\binary_realtime_loso_per_scenario.csv"
    "reports\fault_protocol_e_audited_d1_loso.csv"
    "reports\fault_protocol_e_audited_d2_loso.csv"
    "reports\fault_protocol_e_audited_d1_per_class.csv"
    "reports\fault_protocol_e_audited_d2_per_class.csv"
    "reports\fault_protocol_e_d1_loso.csv"
    "reports\fault_protocol_e_d2_loso.csv"
    "reports\fault_protocol_e_d1_per_class.csv"
    "reports\fault_protocol_e_d2_per_class.csv"
    "reports\realtime_binary_artifact_benchmark.csv"
    "reports\grouped_real_only_summary.csv"
    "reports\environment_lock.txt"
    "reports\scenario_inventory.csv"
    "scripts\pack_review_for_ai.ps1"
)

# Helpful if present; skip quietly.
$Optional = @(
    "tests\test_mitigation_policy.py"
    "tests\test_model_catalog.py"
    "tests\test_dashboard_endpoints.py"
    "tests\conftest.py"
    "dataset\fault_stats_grouped_e.csv"
    "reports\fault_protocol_d1_loso.csv"
    "reports\fault_protocol_d2_loso.csv"
    "reports\fault_protocol_d1_per_class.csv"
    "reports\fault_protocol_d2_per_class.csv"
    "reports\fault_protocol_e_audited_d2_ablation_loso.csv"
    "reports\fault_protocol_e_audited_d2_random_forest_confusion.csv"
    "reports\fault_protocol_e_audited_d1_random_forest_confusion.csv"
    "reports\model_comparison.csv"
    "src\eval_fault_ablation.py"
    "src\train_realtime_binary.py"
    "controller\label_helper.py"
)

foreach ($rel in $Must) { Add-PackFile -Rel $rel }
foreach ($rel in $Optional) { Add-PackFile -Rel $rel -Optional }

# Schema note: header + counts. Do NOT pack the 96 MB CSV.
$SchemaRel = "reports\DATASET_SCHEMA_NOTE.md"
$SchemaPath = Join-Path $Staging $SchemaRel
New-Item -ItemType Directory -Force -Path (Split-Path $SchemaPath -Parent) | Out-Null

$SchemaOk = $false
$PyCmd = Get-Command python -ErrorAction SilentlyContinue
if ($PyCmd) {
    $PyCode = @'
from pathlib import Path
import csv
import sys
from collections import Counter

root = Path(sys.argv[1])
out = Path(sys.argv[2])

def peek(path, max_preview=5):
    p = root / path
    info = {
        "rel": path.replace("\\", "/"),
        "exists": p.exists(),
        "bytes": p.stat().st_size if p.exists() else 0,
        "lines": 0,
        "preview": [],
        "label_counts": {},
        "n_run": None,
        "n_scenario": None,
    }
    if not p.exists():
        return info
    with p.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return info
        info["preview"].append(",".join(header))
        info["lines"] = 1
        cols = {name: i for i, name in enumerate(header)}
        li, ri, si = cols.get("label"), cols.get("run_id"), cols.get("scenario_id")
        labels = Counter()
        runs, scenarios = set(), set()
        for row in reader:
            info["lines"] += 1
            if len(info["preview"]) < max_preview:
                info["preview"].append(",".join(row))
            if li is not None and li < len(row):
                labels[row[li]] += 1
            if ri is not None and ri < len(row):
                runs.add(row[ri])
            if si is not None and si < len(row):
                scenarios.add(row[si])
        info["label_counts"] = dict(labels)
        if ri is not None:
            info["n_run"] = len(runs)
        if si is not None:
            info["n_scenario"] = len(scenarios)
    return info

targets = [
    "dataset/flow_stats_grouped.csv",
    "dataset/fault_stats_grouped_e.csv",
    "dataset/fault_stats_grouped.csv",
]
lines = [
    "# Dataset schema note (generated; the 326k CSV is NOT in this pack)",
    "",
    "`dataset/flow_stats_grouped.csv` is ~96 MB. It is excluded on purpose.",
    "**Trust `reports/*.csv` for Acc/F1.** This note is a streaming header/count only.",
    "",
]
for info in (peek(t) for t in targets):
    rel = info["rel"]
    lines.append(f"## `{rel}`")
    if not info["exists"]:
        lines.append("Missing on the machine that packed this zip.")
        lines.append("")
        continue
    rows = max(info["lines"] - 1, 0)
    mb = info["bytes"] / (1024 * 1024)
    lines.append(f"- Size: **{mb:.2f} MB** ({info['bytes']} bytes)")
    lines.append(f"- Lines (incl. header): **{info['lines']}** → data rows **{rows}**")
    if info["n_run"] is not None:
        lines.append(f"- Distinct `run_id`: **{info['n_run']}**")
    if info["n_scenario"] is not None:
        lines.append(f"- Distinct `scenario_id`: **{info['n_scenario']}**")
    if info["label_counts"]:
        pretty = ", ".join(f"{k}={v}" for k, v in sorted(info["label_counts"].items()))
        lines.append(f"- `label` counts: {pretty}")
    lines.append("")
    lines.append("First <=5 lines:")
    lines.append("")
    lines.append("```")
    lines.extend(info["preview"])
    lines.append("```")
    lines.append("")
lines.append("Do not treat ~326,961 poll snapshots as 326,961 i.i.d. sessions.")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("WROTE", out)
'@
    $PyFile = Join-Path $TmpDir "_schema_note.py"
    [System.IO.File]::WriteAllText($PyFile, $PyCode)
    try {
        & python $PyFile $Root $SchemaPath
        if (Test-Path -LiteralPath $SchemaPath) {
            $SchemaOk = $true
            [void]$Packed.Add($SchemaRel)
        }
    } catch {
        Write-Warning "Python schema note failed: $_"
    } finally {
        if (Test-Path -LiteralPath $PyFile) { Remove-Item -LiteralPath $PyFile -Force }
    }
}

if (-not $SchemaOk) {
    $fallback = @"
# Dataset schema note (fallback — Python count did not run)

Pack machine could not stream-count CSVs. Use README.md locked counts:

- ``dataset/flow_stats_grouped.csv``: **326,961** snapshots, **206** run_id, **21** scenario_id (excluded from zip, ~96 MB)
- ``dataset/fault_stats_grouped_e.csv``: **1,982** rows, **112** run, **36** scenario (packed if present)
- ``dataset/fault_stats_grouped.csv``: Protocol D historical **6,666** rows (not packed; appendix)

Trust ``reports/*.csv`` for metrics. Do not invent Acc.
"@
    [System.IO.File]::WriteAllText($SchemaPath, $fallback)
    [void]$Packed.Add($SchemaRel)
}

$LiveSchema = Join-Path $Root "reports\DATASET_SCHEMA_NOTE.md"
Copy-Item -LiteralPath $SchemaPath -Destination $LiveSchema -Force

$ExcludedWhy = @"
EXCLUDED (do not ask the other AI to open the full repo for these)

- .venv / venv                local Python env; not evidence
- __pycache__ / *.pyc         bytecode
- tmp/ (except this zip)      staging + generated packs
- dataset/flow_stats_grouped.csv
    ~96 MB, ~326,961 poll snapshots. Too large for a review chat.
    Counts/header: reports/DATASET_SCHEMA_NOTE.md
    Metrics: reports/binary_realtime_loso_summary.csv and per-scenario CSV
- dataset/flow_stats.csv      monitor dump; not the headline pool
- dataset/train.csv, test.csv legacy random-flow split (Acc ~0.999 leakage) — not packed
- dataset/fault_runs/         raw Protocol E capture trees
- dataset/fault_runs_legacy/  Protocol D raw
- dataset/live_stats.json, alerts.json, controller.pid   live demo state
- models/*.pkl, *.keras       RF-binary pickle can be 10-20 MB.
    Latency is in reports/realtime_binary_artifact_benchmark.csv (p50 ~12.99 ms).
    Do not unpickle to 'verify Acc'.
- KhoaLuanTotNghiep.docx / KLTN.pdf / Thesis Defense Presentation (1).pptx
    Intentionally NOT packed. Treat Word/slides as UNVERIFIED from this zip.
    Flag leftover overclaims listed in docs/CAM_NANG_BAO_VE_FULL.md (Word/slide punch lists).
- reports/public_benchmark/   CICIDS/InSDN appendix; not the train set
- reports/thesis_shots/       screenshot dumps
- .git                        not needed
"@

$packLines = @()
foreach ($rel in ($Packed | Sort-Object -Unique)) {
    $full = Join-Path $Staging $rel
    if (Test-Path -LiteralPath $full) {
        $len = (Get-Item -LiteralPath $full).Length
        $packLines += ("{0}`t{1} bytes" -f $rel, $len)
    } else {
        $packLines += $rel
    }
}
$missLines = if ($Missing.Count -gt 0) { @($Missing) } else { @("(none)") }
$optLines = if ($SkippedOptional.Count -gt 0) { @($SkippedOptional) } else { @("(none)") }

$Manifest = @"
SDN anomaly-detection ML — AI review pack
Packed: $Stamp
Git HEAD: $GitSha
Repo root: $Root

HOW TO USE
1. Unzip this archive.
2. Read docs/PROMPT_PHAN_BIEN_AI.md in full (same text the student pastes).
3. Verify every numeric claim against reports/*.csv. CSV wins over README/docs.
4. Do not invent a better Accuracy. Do not treat 326k snapshots as i.i.d.

HEADLINE LOCKS (re-check in CSV)
- Anomaly LOSO RF Acc ~0.7724  -> reports/binary_realtime_loso_summary.csv
- Min attack-scenario recall = 0 (portscan_nmap_h4_h1) -> binary_realtime_loso_per_scenario.csv
- Fault Protocol E audited D2 RF Acc ~0.9250 / F1-macro ~0.9281
  -> reports/fault_protocol_e_audited_d2_loso.csv  (_pooled row)
- Inference p50 ~12.99 ms != mitigation E2E
  -> reports/realtime_binary_artifact_benchmark.csv
- Live artifact: random_forest_binary (8 features) -> dataset/controller_config.json
- Pre-audit files reports/fault_protocol_e_d1_loso.csv and d2_loso.csv may differ
  slightly from *_audited_*. Headline = audited.

INCLUDED FILES
$($packLines -join "`n")

MUST-HAVE MISSING ON PACK MACHINE
$($missLines -join "`n")

OPTIONAL SKIPPED (not on disk)
$($optLines -join "`n")

$ExcludedWhy
"@

$ManifestPath = Join-Path $Staging "MANIFEST.txt"
[System.IO.File]::WriteAllText($ManifestPath, $Manifest)
[void]$Packed.Add("MANIFEST.txt")

if (Test-Path -LiteralPath $OutZip) {
    Remove-Item -LiteralPath $OutZip -Force
}
$zipParent = Split-Path -Parent $OutZip
if ($zipParent -and -not (Test-Path -LiteralPath $zipParent)) {
    New-Item -ItemType Directory -Force -Path $zipParent | Out-Null
}

Compress-Archive -Path (Join-Path $Staging "*") -DestinationPath $OutZip -CompressionLevel Optimal -Force

$ZipItem = Get-Item -LiteralPath $OutZip
$ZipMb = [math]::Round($ZipItem.Length / 1MB, 2)

if ($CopyToDesktop) {
    $desk = [Environment]::GetFolderPath("Desktop")
    if ($desk) {
        $deskZip = Join-Path $desk "sdn_ml_review_pack.zip"
        Copy-Item -LiteralPath $OutZip -Destination $deskZip -Force
        Write-Host "Copied to Desktop: $deskZip"
    }
}

Write-Host ""
Write-Host "Packed $($Packed.Count) paths"
Write-Host "Missing must-have: $($Missing.Count)"
Write-Host "Optional skipped: $($SkippedOptional.Count)"
Write-Host "ZIP: $($ZipItem.FullName)"
Write-Host "SIZE: $($ZipItem.Length) bytes ($ZipMb MB)"
if ($ZipMb -gt 20) {
    Write-Warning "Zip is $ZipMb MB (>20). Check whether a large optional file slipped in."
}
Write-Host "Staging left at: $Staging"

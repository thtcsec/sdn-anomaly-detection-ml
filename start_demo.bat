@echo off
chcp 65001 > nul
echo ============================================================
echo   KHỞI ĐỘNG HỆ THỐNG SDN ANOMALY DETECTION (3 TERMINALS)
echo ============================================================
echo.

where wt >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [*] Phát hiện Windows Terminal (wt.exe) - Mở 3 tabs tự động...
    start wt -w 0 nt --title "1. Controller (Realtime)" wsl -u root bash -c "cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && source .venv/bin/activate && python controller/run_realtime.py; exec bash" ; ^
          sp -V --title "2. Dashboard (Port 5000)" wsl -u root bash -c "cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && source .venv/bin/activate && python dashboard/app.py; exec bash" ; ^
          sp -H --title "3. Mininet (Traffic CLI)" wsl -u root bash -c "cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && mn -c >/dev/null 2>&1; /usr/bin/python3 topology/custom_topo.py; exec bash"
) else (
    echo [*] Mở 3 cửa sổ CMD riêng biệt...
    start "1. Controller (Realtime)" cmd /k "wsl -u root bash -c \"cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && source .venv/bin/activate && python controller/run_realtime.py\""
    timeout /t 3 /nobreak > nul
    start "2. Dashboard (Port 5000)" cmd /k "wsl -u root bash -c \"cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && source .venv/bin/activate && python dashboard/app.py\""
    timeout /t 2 /nobreak > nul
    start "3. Mininet (Traffic CLI)" cmd /k "wsl -u root bash -c \"cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && mn -c >/dev/null 2>&1; /usr/bin/python3 topology/custom_topo.py\""
)

echo [✓] Đã khởi động xong 3 terminals!
echo [✓] Dashboard Web: http://127.0.0.1:5000
echo.
pause

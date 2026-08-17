# Khởi động 3 cửa sổ demo SDN Anomaly Detection
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  KHỞI ĐỘNG HỆ THỐNG SDN ANOMALY DETECTION DEMO             " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[0/3] Dọn controller/dashboard cũ trên cổng 6633 và 5000..." -ForegroundColor Yellow
wsl -u root bash -c 'pkill -f controller/run_realtime.py || true; pkill -f controller/run_fault_monitor.py || true; pkill -f dashboard/app.py || true'
Start-Sleep -Seconds 2

Write-Host "[1/3] Đang mở Controller Realtime (os-ken + ML)..." -ForegroundColor Yellow
Start-Process cmd -ArgumentList '/k', 'wsl -u root bash -c "cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && source .venv/bin/activate && python controller/run_realtime.py; exec bash"'

Start-Sleep -Seconds 8

Write-Host "[2/3] Đang mở Dashboard SOC (Port 5000)..." -ForegroundColor Yellow
Start-Process cmd -ArgumentList '/k', 'wsl -u root bash -c "cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && source .venv/bin/activate && python dashboard/app.py; exec bash"'

Start-Sleep -Seconds 2

Write-Host "[3/3] Đang mở Mininet Network Topology..." -ForegroundColor Yellow
Start-Process cmd -ArgumentList '/k', 'wsl -u root bash -c "cd /mnt/d/tu_projects/sdn-anomaly-detection-ml && mn -c >/dev/null 2>&1; /usr/bin/python3 topology/custom_topo.py; exec bash"'

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "[✓] Đã khởi động xong cả 3 cửa sổ Terminal!" -ForegroundColor Green
Write-Host "[✓] Truy cập Dashboard Web tại: http://localhost:5000" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Green

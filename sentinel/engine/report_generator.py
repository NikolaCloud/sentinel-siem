"""
Генератор аудиторских отчетов ИБ и сводок для CISO / Руководства.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from sentinel.config import REPORTS_DIR


class SecurityReportGenerator:
    @staticmethod
    def generate_html_report(incidents: List[Dict[str, Any]], metrics: Dict[str, Any], output_path: Optional[Path] = None) -> Path:
        output_file = output_path or (REPORTS_DIR / f"siem_incident_report_{int(datetime.now().timestamp())}.html")

        incident_rows = []
        for inc in incidents:
            sev = inc.get("severity", "LOW")
            sev_color = "#dc2626" if sev == "CRITICAL" else ("#ef4444" if sev == "HIGH" else ("#f59e0b" if sev == "MEDIUM" else "#3b82f6"))
            payload_str = f"<code>{inc.get('payload')}</code>" if inc.get('payload') else "—"

            incident_rows.append(f"""
            <tr>
                <td>#{inc.get('id')}</td>
                <td><span style="background:{sev_color}; color:#fff; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:bold;">{sev}</span></td>
                <td><b>{inc.get('rule_name')}</b><br><small style="color:#64748b;">MITRE: {inc.get('mitre_id')}</small></td>
                <td><code>{inc.get('source_ip')}</code></td>
                <td>{payload_str}</td>
                <td><span class="badge-status">{inc.get('status')}</span></td>
                <td>{inc.get('created_at')}</td>
            </tr>
            """)

        top_ips_html = "".join([f"<li><b>{ip['source_ip']}</b> — {ip['cnt']} инцидентов</li>" for ip in metrics.get("top_ips", [])])
        mitre_html = "".join([f"<span class='mitre-tag'>{m['mitre_id']} ({m['cnt']})</span>" for m in metrics.get("mitre_dist", [])])

        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Sentinel SIEM — Отчет об инцидентах информационной безопасности</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background: #0f172a; color: #f8fafc; padding: 40px; line-height: 1.5; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-end; }}
  .logo {{ font-size: 24px; font-weight: 800; color: #f8fafc; }}
  .logo span {{ color: #ef4444; }}
  
  .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
  .kpi-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; }}
  .kpi-title {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }}
  .kpi-val {{ font-size: 26px; font-weight: 800; margin-top: 6px; }}

  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 24px; margin-bottom: 24px; }}
  .card-title {{ font-size: 16px; font-weight: 700; color: #e2e8f0; margin-bottom: 14px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
  
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; color: #94a3b8; padding: 10px; border-bottom: 1px solid #334155; font-size: 11px; text-transform: uppercase; }}
  td {{ padding: 10px; border-bottom: 1px solid #283548; color: #cbd5e1; }}
  code {{ font-family: Consolas, monospace; background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #f87171; }}
  .badge-status {{ background: #0f172a; border: 1px solid #334155; padding: 2px 6px; border-radius: 4px; font-size: 11px; }}
  .mitre-tag {{ display: inline-block; background: #312e81; color: #a5b4fc; font-weight: 600; font-size: 11px; padding: 4px 10px; border-radius: 6px; margin: 3px; }}
  .recom-box {{ background: #064e3b; border: 1px solid #059669; border-radius: 8px; padding: 16px; color: #d1fae5; font-size: 13px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="logo"><span>🛡️</span> Sentinel SIEM — SOC Incident Report</div>
      <div style="color:#94a3b8; font-size:13px; margin-top:4px;">Сводка расследования событий информационной безопасности</div>
    </div>
    <div style="text-align:right; font-size:12px; color:#94a3b8;">
      Дата выгрузки: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}<br>
      Классификатор: MITRE ATT&CK Enterprise
    </div>
  </div>

  <div class="kpi-row">
    <div class="kpi-card">
      <div class="kpi-title">Всего событий в базе</div>
      <div class="kpi-val" style="color:#38bdf8;">{metrics.get('total_events', 0)}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Зафиксировано атак</div>
      <div class="kpi-val" style="color:#f59e0b;">{metrics.get('total_incidents', 0)}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Критических угроз (P1)</div>
      <div class="kpi-val" style="color:#ef4444;">{metrics.get('critical_count', 0)}</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Уникальных атакующих IP</div>
      <div class="kpi-val" style="color:#a855f7;">{metrics.get('unique_attackers', 0)}</div>
    </div>
  </div>

  <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-bottom:24px;">
    <div class="card">
      <div class="card-title">🚨 Топ источников атак (Attacker IPs)</div>
      <ul style="padding-left: 20px; font-size:13px; line-height: 1.8;">
        {top_ips_html}
      </ul>
    </div>
    <div class="card">
      <div class="card-title">🎯 Задействованные техники MITRE ATT&CK</div>
      <div>
        {mitre_html}
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">📋 Журнал зарегистрированных инцидентов</div>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Критичность</th>
          <th>Правило / Сигнатура</th>
          <th>IP источника</th>
          <th>Полезная нагрузка (Payload)</th>
          <th>Статус</th>
          <th>Время</th>
        </tr>
      </thead>
      <tbody>
        {''.join(incident_rows)}
      </tbody>
    </table>
  </div>

  <div class="recom-box">
    <b>💡 Рекомендации дежурного инженера SOC:</b><br>
    1. Немедленно добавить IP-адреса <code>198.51.100.45</code> и <code>45.33.32.156</code> в черные списки Firewall (iptables / WAF).<br>
    2. Провести аудит аккаунта <code>Administrator</code> в связи с фиксацией входа во внерабочее время.<br>
    3. Настроить WAF для фильтрации символов <code>UNION SELECT</code> и <code>../..</code> на уровне Nginx ingress.
  </div>
</div>
</body>
</html>"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        return output_file


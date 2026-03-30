# ========== Python 3.8 兼容性修复（必须放在文件最顶部）==========
import sys
import hashlib

if sys.version_info < (3, 9):
    # 保存原始 md5 函数
    _original_md5 = hashlib.md5


    # 创建兼容包装器，接受 usedforsecurity 参数但忽略它
    def _patched_md5(data=b'', *, usedforsecurity=True):
        return _original_md5(data)


    # 替换 hashlib.md5
    hashlib.md5 = _patched_md5

    # 预 patch reportlab 内部使用的 md5（如果已经导入则 patch，否则在导入时 patch）
    try:
        from reportlab.pdfbase import pdfdoc

        pdfdoc.md5 = _patched_md5
    except ImportError:
        pass  # reportlab 还没导入，等它导入时会自动使用我们的 patch

# ===============================================================
from core.storage.database import Database
from flask import Blueprint, render_template, jsonify, request, send_file
from core.vulnerability.scanner.engine import ScanEngine as VulnScannerEngine
import threading
import json
import sqlite3
import socket
import platform
import io
import os
from datetime import datetime

# ========== 先创建蓝图 ==========
device_bp = Blueprint('device', __name__)

# ========== 流量监控全局实例（新增）==========
from core.network.traffic_rate import TrafficMonitor

traffic_monitor = TrafficMonitor(interval=5)
traffic_monitor.start_monitoring()
print("[+] 流量监控服务已启动")

# ========== 流量监控API（新增）==========

@device_bp.route('/api/traffic/current')
def get_traffic():
    """获取当前实时网速"""
    try:
        stats = traffic_monitor.get_current_stats()
        return jsonify({
            'status': 'success',
            'upload_mbps': round(stats.get('upload_speed_bps', 0) / 1_000_000, 2),
            'download_mbps': round(stats.get('download_speed_bps', 0) / 1_000_000, 2),
            'connections': stats.get('total_connections', 0),
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@device_bp.route('/api/traffic/history')
def get_traffic_history():
    """获取历史流量趋势（用于图表）"""
    try:
        count = request.args.get('count', 20, type=int)
        history = traffic_monitor.get_history(count=count)
        return jsonify({
            'status': 'success',
            'data': history
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# 数据库连接辅助函数（自动建表）
def create_connection(db_path=None):
    """创建数据库连接（自动创建设备表）"""
    conn = sqlite3.connect(db_path or 'data/devices.db')
    cursor = conn.cursor()

    # 自动创建设备表（如果不存在）
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            mac TEXT,
            vendor TEXT,
            device_type TEXT,
            status TEXT DEFAULT 'unknown',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_scan TIMESTAMP,
            open_ports TEXT,
            services TEXT,
            risk_score REAL DEFAULT 0.0
        )
    ''')
    conn.commit()
    return conn


# ========== 设备列表路由 ==========
@device_bp.route('/')
def index():
    """设备列表页面"""
    conn = create_connection('data/devices.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE ip != 'unknown' AND mac != 'unknown'")
    devices = cursor.fetchall()
    conn.close()

    device_list = []
    for d in devices:
        device_list.append({
            'id': d[0],
            'ip': d[1],
            'mac': d[2],
            'vendor': d[3],
            'device_type': d[4] if len(d) > 4 else 'Unknown',
            'created_at': d[5] if len(d) > 5 else None
        })

    return render_template('index.html', devices=device_list)


# ========== 设备详情路由 ==========
@device_bp.route('/device/<mac>')
def device_detail(mac):
    """设备详情页面 - 专注主动漏洞扫描"""
    conn = create_connection('data/devices.db')
    cursor = conn.cursor()

    # 获取设备信息
    cursor.execute("SELECT * FROM devices WHERE mac=?", (mac,))
    device = cursor.fetchone()

    if not device:
        conn.close()
        return "Device not found", 404

    device_dict = {
        'id': device[0],
        'ip': device[1],
        'mac': device[2],
        'vendor': device[3],
        'device_type': device[4] if len(device) > 4 else 'Unknown',
        'created_at': device[5] if len(device) > 5 else None
    }

    # 创建 active_vuln_results 表（如果不存在）
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_vuln_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT,
                device_mac TEXT,
                device_type TEXT,
                scan_time TEXT,
                vuln_type TEXT,
                severity TEXT,
                description TEXT,
                proof TEXT,
                fix_suggestion TEXT
            )
        ''')
        conn.commit()
    except:
        pass

    # 查询主动漏洞扫描历史
    vulnerabilities = []
    try:
        cursor.execute('''
            SELECT vuln_type, severity, description, proof, fix_suggestion, scan_time 
            FROM active_vuln_results 
            WHERE device_mac=? OR device_ip=?
            ORDER BY scan_time DESC
        ''', (mac, device_dict['ip']))
        rows = cursor.fetchall()

        for row in rows:
            vulnerabilities.append({
                'type': row[0],
                'severity': row[1],
                'description': row[2],
                'proof': row[3],
                'fix': row[4],
                'scan_time': row[5]
            })
    except Exception as e:
        print(f"查询漏洞历史失败: {e}")

    conn.close()

    # 计算风险评分
    risk_score = 0
    if vulnerabilities:
        weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        risk_score = min(sum(weights.get(v['severity'], 0) for v in vulnerabilities), 10)

    return render_template('device_detail.html',
                           device=device_dict,
                           vulnerabilities=vulnerabilities,
                           scan_history={'vuln_count': len(vulnerabilities),
                                         'risk_score': risk_score} if vulnerabilities else None)


# ========== 手动扫描测试页面 ==========
@device_bp.route('/test/manual')
def manual_scan_page():
    """手动扫描测试页面 - 用于测试漏洞检测"""
    return render_template('manual_scan.html')


# ========== 手动扫描 API ==========
@device_bp.route('/api/scan/manual', methods=['POST'])
def manual_scan():
    """
    手动扫描指定目标 - 用于测试漏洞检测
    请求体: {
        "ip": "127.0.0.1",
        "ports": [8080, 2323, 8000],
        "device_type": "router_gateway",
        "mac": "00:00:00:00:00:00"
    }
    """
    data = request.get_json()

    if not data or not data.get('ip'):
        return jsonify({'error': '缺少目标 IP 地址'}), 400

    # 构建设备信息
    target_device = {
        'ip': data.get('ip'),
        'mac': data.get('mac', '00:00:00:00:00:00'),
        'open_ports': data.get('ports', [80, 8080, 23, 2323, 8000, 1883]),
        'device_type': data.get('device_type', 'unknown'),
        'manufacturer': data.get('manufacturer', 'Test Device')
    }

    print(f"\n[手动扫描请求] 目标: {target_device['ip']}, 端口: {target_device['open_ports']}")

    # 执行扫描（同步执行，等待结果）
    engine = VulnScannerEngine()

    try:
        result = engine.scan_device(target_device)

        # 计算漏洞统计（兼容处理）
        all_vulnerabilities = []

        # 处理CVE漏洞（修改后的兼容代码）
        for v in result.get('vulnerabilities', []):
            if isinstance(v, dict):
                # 优先使用 cve_id 或 title 作为漏洞名称
                vuln_name = v.get('cve_id') or v.get('title') or v.get('type') or 'Unknown Vulnerability'
                all_vulnerabilities.append({
                    'type': vuln_name,
                    'severity': v.get('severity', 'Medium'),
                    'description': v.get('description', v.get('title', '')),
                    'proof': v.get('proof', ''),
                    'fix': v.get('solution', v.get('fix', ''))
                })
            elif hasattr(v, 'cve_id'):
                all_vulnerabilities.append({
                    'type': v.cve_id,
                    'severity': v.severity,
                    'description': v.title if hasattr(v, 'title') else str(v),
                    'proof': '',
                    'fix': v.solution if hasattr(v, 'solution') else ''
                })

        # 处理认证问题
        for v in result.get('auth_issues', []):
            if hasattr(v, 'issue_type'):
                all_vulnerabilities.append({
                    'type': f"Auth-{v.issue_type}",
                    'severity': v.severity,
                    'description': v.details if hasattr(v, 'details') else str(v),
                    'proof': '',
                    'fix': v.recommendation if hasattr(v, 'recommendation') else ''
                })
            elif isinstance(v, dict):
                all_vulnerabilities.append({
                    'type': v.get('type', 'Auth Issue'),
                    'severity': v.get('severity', 'Medium'),
                    'description': v.get('details', str(v)),
                    'proof': v.get('proof', ''),
                    'fix': v.get('recommendation', v.get('fix', ''))
                })

        # 处理协议问题
        for v in result.get('protocol_issues', []):
            if isinstance(v, dict):
                all_vulnerabilities.append({
                    'type': v.get('protocol', 'Protocol Issue'),
                    'severity': v.get('severity', 'Medium'),
                    'description': v.get('issue', v.get('description', '')),
                    'proof': '',
                    'fix': v.get('recommendation', v.get('fix', ''))
                })

        vuln_count = len(all_vulnerabilities)

        # 计算风险评分
        weights = {'Critical': 10, 'HIGH': 7, 'High': 7, 'MEDIUM': 4, 'Medium': 4, 'LOW': 1, 'Low': 1}
        risk_score = min(sum(weights.get(v.get('severity', 'Low'), 1) for v in all_vulnerabilities), 10)

        # 保存结果到数据库
        if all_vulnerabilities:
            conn = create_connection('data/devices.db')
            cursor = conn.cursor()

            # 确保表存在
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS active_vuln_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ip TEXT,
                    device_mac TEXT,
                    device_type TEXT,
                    scan_time TEXT,
                    vuln_type TEXT,
                    severity TEXT,
                    description TEXT,
                    proof TEXT,
                    fix_suggestion TEXT
                )
            ''')

            # 插入漏洞记录
            for vuln in all_vulnerabilities:
                cursor.execute('''
                    INSERT INTO active_vuln_results 
                    (device_ip, device_mac, device_type, scan_time, vuln_type, severity, description, proof, fix_suggestion)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    target_device['ip'],
                    target_device['mac'],
                    target_device['device_type'],
                    datetime.now().isoformat(),
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'MEDIUM'),
                    vuln.get('description', ''),
                    vuln.get('proof', ''),
                    vuln.get('fix', '')
                ))

            conn.commit()
            conn.close()

            try:
                db = Database()  # 使用统一的数据库类
                for vuln in all_vulnerabilities:
                    db.add_vulnerability(
                        device_ip=target_device['ip'],
                        vuln={
                            'cve_id': vuln.get('type', 'UNKNOWN'),
                            'title': vuln.get('description', 'Unknown')[:50],  # 截取前50字作为标题
                            'description': vuln.get('description', ''),
                            'severity': vuln.get('severity', 'Medium'),
                            'cvss_score': weights.get(vuln.get('severity', 'Low'), 5.0),
                            'solution': vuln.get('fix', '')
                        }
                    )
                print(f"[+] 已同步保存 {len(all_vulnerabilities)} 个漏洞到 vulnerabilities 表")
            except Exception as e:
                print(f"[!] 保存到 vulnerabilities 表失败: {e}")

            print(f"[+] 已保存 {len(all_vulnerabilities)} 个漏洞到数据库")



        return jsonify({
            'status': 'success',
            'message': f"扫描完成，发现 {vuln_count} 个漏洞",
            'target': target_device,
            'result': {
                'vuln_count': vuln_count,
                'risk_score': risk_score,
                'vulnerabilities': all_vulnerabilities
            }
        })

    except Exception as e:
        import traceback
        error_msg = str(e)
        print(f"[手动扫描失败] {error_msg}")
        print(traceback.format_exc())
        return jsonify({
            'status': 'error',
            'message': error_msg,
            'traceback': traceback.format_exc()
        }), 500


# ========== 网络扫描 API ==========
@device_bp.route('/api/scan/network', methods=['POST'])
def scan_network():
    """扫描整个局域网（ARP扫描）"""
    try:
        # 获取本机IP并推断网段
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # 推断网段 (如 192.168.31.136 -> 192.168.31.0/24)
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except:
            network = "192.168.1.0/24"  # 默认网段

        print(f"\n[网络扫描请求] 网段: {network}")

        from core.network.arp_scanner import ARPScanner
        from core.network.device_identifier import DeviceIdentifier

        # 执行ARP扫描
        scanner = ARPScanner(network, timeout=2, max_workers=50)
        devices = scanner.scan()

        print(f"[+] ARP扫描完成，发现 {len(devices)} 个设备")

        # 识别厂商并保存到数据库
        identifier = DeviceIdentifier('data/oui.txt')
        conn = create_connection('data/devices.db')
        cursor = conn.cursor()

        new_devices = 0
        updated_devices = 0

        for device in devices:
            # 识别厂商
            vendor = identifier.identify(device.mac)
            device_type = "Unknown"

            # 简单的设备类型推断
            if vendor:
                vendor_lower = vendor.lower()
                if any(x in vendor_lower for x in ['router', 'gateway', 'tp-link', 'huawei', 'xiaomi']):
                    device_type = "路由器/网关"
                elif any(x in vendor_lower for x in ['camera', 'ipc', 'dahua', 'hikvision']):
                    device_type = "摄像头"
                elif any(x in vendor_lower for x in ['phone', 'mobile', 'apple', 'samsung', 'xiaomi']):
                    device_type = "手机/平板"
                elif any(x in vendor_lower for x in ['computer', 'intel', 'dell', 'hp', 'lenovo']):
                    device_type = "计算机/服务器"

            # 检查是否已存在
            cursor.execute("SELECT id FROM devices WHERE mac=?", (device.mac,))
            existing = cursor.fetchone()

            if not existing:
                # 插入新设备
                cursor.execute('''
                    INSERT INTO devices (ip, mac, vendor, device_type, status, first_seen, last_scan)
                    VALUES (?, ?, ?, ?, 'online', datetime('now'), datetime('now'))
                ''', (device.ip, device.mac, vendor, device_type))
                new_devices += 1
            else:
                # 更新现有设备
                cursor.execute('''
                    UPDATE devices SET ip=?, vendor=?, device_type=?, status='online', last_scan=datetime('now')
                    WHERE mac=?
                ''', (device.ip, vendor, device_type, device.mac))
                updated_devices += 1

        conn.commit()
        conn.close()

        return jsonify({
            'status': 'success',
            'message': f'扫描完成！发现 {len(devices)} 个设备（新增 {new_devices} 个，更新 {updated_devices} 个）',
            'devices_found': len(devices),
            'new_devices': new_devices,
            'updated_devices': updated_devices,
            'network': network
        })

    except PermissionError as e:
        print(f"[网络扫描失败] 权限不足: {e}")
        return jsonify({
            'status': 'error',
            'message': '权限不足，请以管理员身份运行程序（Windows右键以管理员身份运行CMD）'
        }), 403
    except Exception as e:
        import traceback
        print(f"[网络扫描失败] {e}")
        print(traceback.format_exc())
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ========== PDF报告导出 API（完整版）==========
@device_bp.route('/api/report/pdf/<mac>')
def generate_pdf_report(mac):
    """生成并下载PDF安全报告"""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.graphics.shapes import Drawing, Rect, String
        from reportlab.graphics.charts.piecharts import Pie
        import platform

        # 获取设备信息
        conn = create_connection('data/devices.db')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM devices WHERE mac=?", (mac,))
        device_row = cursor.fetchone()

        if not device_row:
            conn.close()
            return jsonify({'error': '设备不存在'}), 404

        device_data = {
            'ip': device_row[1],
            'mac': device_row[2],
            'vendor': device_row[3] or 'Unknown',
            'device_type': device_row[4] or 'Unknown',
            'status': device_row[5] or 'unknown',
            'first_seen': device_row[6] or 'N/A',
            'last_scan': device_row[7] or 'N/A'
        }

        # 获取漏洞历史
        cursor.execute('''
            SELECT vuln_type, severity, description, proof, fix_suggestion, scan_time 
            FROM active_vuln_results 
            WHERE device_mac=? OR device_ip=?
            ORDER BY 
                CASE severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'HIGH' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                scan_time DESC
        ''', (mac, device_data['ip']))

        vulnerabilities = []
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        weights = {'Critical': 10, 'HIGH': 7, 'High': 7, 'MEDIUM': 4, 'Medium': 4, 'LOW': 1, 'Low': 1}
        total_risk = 0

        for row in cursor.fetchall():
            vuln = {
                'type': row[0],
                'severity': row[1],
                'description': row[2] or '暂无描述',
                'proof': row[3] or '无',
                'fix': row[4] or '建议联系厂商更新固件或禁用相关服务',
                'scan_time': row[5] or 'N/A'
            }
            vulnerabilities.append(vuln)

            # 统计严重程度
            sev = row[1] if row[1] else 'Low'
            if sev in ['CRITICAL', 'Critical']:
                severity_count['Critical'] += 1
            elif sev in ['HIGH', 'High']:
                severity_count['High'] += 1
            elif sev in ['MEDIUM', 'Medium']:
                severity_count['Medium'] += 1
            else:
                severity_count['Low'] += 1

            total_risk += weights.get(sev, 1)

        conn.close()

        # 计算风险评分 (0-10)
        risk_score = min(total_risk, 10) if vulnerabilities else 0

        # 确定风险等级
        if risk_score >= 7:
            risk_level = "高危"
            risk_color = colors.HexColor("#DC143C")
        elif risk_score >= 4:
            risk_level = "中危"
            risk_color = colors.HexColor("#FF8C00")
        else:
            risk_level = "低危"
            risk_color = colors.HexColor("#32CD32")

        # ===== 开始生成PDF =====
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )

        # 容器，存放所有要绘制的内容
        elements = []

        # 尝试注册中文字体
        chinese_font = 'Helvetica'  # 默认英文字体
        font_paths = [
            # Windows 常见中文字体
            "C:/Windows/Fonts/simhei.ttf",  # 黑体
            "C:/Windows/Fonts/simsun.ttc",  # 宋体
            "C:/Windows/Fonts/msyh.ttc",  # 微软雅黑
            # Linux 中文字体
            "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            # macOS
            "/System/Library/Fonts/PingFang.ttc",
            "/Library/Fonts/Arial Unicode.ttf"
        ]

        for font_path in font_paths:
            if os.path.exists(font_path):
                try:
                    font_name = "ChineseFont"
                    pdfmetrics.registerFont(TTFont(font_name, font_path))
                    chinese_font = font_name
                    print(f"[PDF] 成功加载字体: {font_path}")
                    break
                except Exception as e:
                    print(f"[PDF] 字体加载失败 {font_path}: {e}")
                    continue

        # 定义样式
        styles = getSampleStyleSheet()

        # 标题样式（使用中文或回退）
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontName=chinese_font,
            fontSize=24,
            textColor=colors.HexColor("#2C3E50"),
            spaceAfter=30,
            alignment=1  # 居中
        )

        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontName=chinese_font,
            fontSize=12,
            textColor=colors.gray,
            alignment=1
        )

        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontName=chinese_font,
            fontSize=14,
            textColor=colors.HexColor("#34495E"),
            spaceAfter=12,
            spaceBefore=12
        )

        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['BodyText'],
            fontName=chinese_font,
            fontSize=10,
            leading=14
        )

        # 封面页
        elements.append(Spacer(1, 2 * cm))
        elements.append(Paragraph("IoT 设备安全评估报告", title_style))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
        elements.append(Spacer(1, 2 * cm))

        # 风险评级卡片
        risk_data = [
            ['风险评级', '漏洞总数', '高危漏洞', '风险评分'],
            [risk_level, str(len(vulnerabilities)), str(severity_count['Critical']), f"{risk_score}/10"]
        ]

        risk_table = Table(risk_data, colWidths=[4 * cm, 3 * cm, 3 * cm, 3 * cm])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#34495E")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), chinese_font),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), chinese_font),
            ('FONTSIZE', (0, 1), (-1, -1), 11),
            ('BACKGROUND', (0, 1), (0, 1), risk_color),  # 风险等级背景色
            ('TEXTCOLOR', (0, 1), (0, 1), colors.white if risk_score >= 4 else colors.black),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 1 * cm))

        # 设备信息部分
        elements.append(Paragraph("设备基本信息", heading_style))
        device_info = [
            ['属性', '数值'],
            ['IP 地址', device_data['ip']],
            ['MAC 地址', device_data['mac']],
            ['设备厂商', device_data['vendor']],
            ['设备类型', device_data['device_type']],
            ['当前状态', device_data['status']],
            ['首次发现', device_data['first_seen']],
            ['最后扫描', device_data['last_scan']]
        ]

        device_table = Table(device_info, colWidths=[4 * cm, 10 * cm])
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#ECF0F1")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), chinese_font),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.gray),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(device_table)
        elements.append(Spacer(1, 1 * cm))

        # 漏洞分布图表（如果有漏洞）
        if vulnerabilities:
            elements.append(Paragraph("漏洞分布统计", heading_style))

            # 创建饼图
            drawing = Drawing(400, 200)
            pie = Pie()
            pie.x = 100
            pie.y = 20
            pie.width = 150
            pie.height = 150
            pie.data = [severity_count['Critical'], severity_count['High'],
                        severity_count['Medium'], severity_count['Low']]
            pie.labels = ['Critical', 'High', 'Medium', 'Low']
            pie.slices.strokeWidth = 0.5
            pie.slices[0].fillColor = colors.HexColor("#DC143C")  # Critical - 红
            pie.slices[1].fillColor = colors.HexColor("#FF8C00")  # High - 橙
            pie.slices[2].fillColor = colors.HexColor("#FFD700")  # Medium - 黄
            pie.slices[3].fillColor = colors.HexColor("#32CD32")  # Low - 绿

            drawing.add(pie)
            elements.append(drawing)
            elements.append(Spacer(1, 0.5 * cm))

        # 漏洞详情部分
        if vulnerabilities:
            elements.append(PageBreak())
            elements.append(Paragraph("漏洞详细清单", heading_style))
            elements.append(Spacer(1, 0.3 * cm))

            # 表头
            vuln_headers = ['序号', '漏洞类型', '严重等级', '发现时间', '修复建议']
            vuln_data = [vuln_headers]

            for idx, vuln in enumerate(vulnerabilities[:20], 1):  # 最多显示20个
                # 根据严重程度设置颜色
                sev = vuln['severity']
                if sev in ['Critical', 'CRITICAL']:
                    color = colors.HexColor("#FFE6E6")  # 浅红背景
                elif sev in ['High', 'HIGH']:
                    color = colors.HexColor("#FFF3E0")  # 浅橙背景
                else:
                    color = colors.white

                row = [
                    str(idx),
                    vuln['type'][:30],  # 截断防止太长
                    sev,
                    vuln['scan_time'][:10],  # 只显示日期部分
                    vuln['fix'][:40] + "..." if len(vuln['fix']) > 40 else vuln['fix']
                ]
                vuln_data.append(row)

            # 创建漏洞表格
            vuln_table = Table(vuln_data, colWidths=[1.5 * cm, 4 * cm, 2.5 * cm, 3 * cm, 6 * cm])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#34495E")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('ALIGN', (1, 1), (1, -1), 'LEFT'),
                ('ALIGN', (4, 1), (4, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), chinese_font),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 1), (-1, -1), chinese_font),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 8),
            ]))

            # 为不同严重程度设置行背景色
            for idx, vuln in enumerate(vulnerabilities[:20], 1):
                sev = vuln['severity']
                if sev in ['Critical', 'CRITICAL']:
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, idx), (-1, idx), colors.HexColor("#FFE6E6")),
                    ]))
                elif sev in ['High', 'HIGH']:
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, idx), (-1, idx), colors.HexColor("#FFF3E0")),
                    ]))

            elements.append(vuln_table)

            if len(vulnerabilities) > 20:
                elements.append(Spacer(1, 0.5 * cm))
                elements.append(Paragraph(f"* 仅显示前20个漏洞，共发现 {len(vulnerabilities)} 个",
                                          ParagraphStyle('Note', parent=normal_style,
                                                         textColor=colors.gray, fontSize=8)))
        else:
            # 使用文字代替符号，避免字体不支持
            elements.append(Paragraph("<b>[通过]</b> 未发现安全漏洞",
                                        ParagraphStyle('GoodNews', parent=heading_style,
                                                        textColor=colors.HexColor("#28a745"))))

        # 安全建议部分
        elements.append(Spacer(1, 1 * cm))
        elements.append(Paragraph("安全加固建议", heading_style))

        # 安全建议 - 使用固定编号确保不跳过
        recommendations = [
            "1. <b>访问控制</b>：修改设备默认管理密码，使用强密码策略（8位以上，含大小写字母和数字）。",
            "2. <b>网络隔离</b>：建议将IoT设备部署在独立VLAN中，与核心业务网络隔离。",
            "3. <b>服务加固</b>：关闭不必要的服务和端口（如Telnet、FTP），仅保留必要的业务端口。",
            "4. <b>持续监控</b>：定期进行漏洞扫描，关注厂商安全公告，及时应用安全补丁。",
            "5. <b>固件更新</b>：启用设备自动更新功能，确保固件为最新版本。",
            "6. <b>物理安全</b>：确保设备放置在安全位置，防止未经授权的物理访问。"
        ]

        # 如果有高危漏洞，在前面插入紧急建议
        if severity_count['Critical'] > 0 or severity_count['High'] > 0:
            recommendations.insert(0, "1. <b>立即处置</b>：存在高危漏洞的设备应当立即断开互联网连接，防止被恶意利用。")
            recommendations.insert(1, "2. <b>紧急修复</b>：尽快更新设备固件至最新版本，修复已知高危漏洞。")
            # 重新编号
            for i, rec in enumerate(recommendations, 1):
                # 替换原有数字编号
                recommendations[i - 1] = rec.replace(rec.split('.')[0], str(i), 1)

        for rec in recommendations:
            elements.append(Paragraph(rec, normal_style))
            elements.append(Spacer(1, 0.2 * cm))

        # 页脚免责声明
        elements.append(Spacer(1, 2 * cm))
        disclaimer = Paragraph(
            "<i>免责声明：本报告由自动化扫描工具生成，仅供参考。实际风险需结合业务场景评估。</i>",
            ParagraphStyle('Disclaimer', parent=normal_style,
                           textColor=colors.gray,
                           fontSize=8,
                           alignment=1)
        )
        elements.append(disclaimer)

        # 生成PDF
        doc.build(elements)
        buffer.seek(0)

        # 返回PDF文件
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"IoT_Security_Report_{mac.replace(':', '-')}_{datetime.now().strftime('%Y%m%d')}.pdf"
        )

    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"[PDF生成失败] {str(e)}")
        print(error_detail)
        return jsonify({
            'error': 'PDF生成失败',
            'message': str(e),
            'detail': error_detail
        }), 500
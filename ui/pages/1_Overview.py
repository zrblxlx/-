import streamlit as st
import sys
import os
import json
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import random

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.utils.global_stats import GlobalStats
from core.storage.database import Database
from core.network.traffic_rate import TrafficMonitor
from ui.common import show_privacy_banner, load_privacy_config, cache_with_ttl
import plotly.express as px
import pandas as pd

st.set_page_config(
    page_title="网络概览",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

with st.sidebar:
    st.title("📋 导航菜单")
    st.page_link("pages/1_Overview.py", label="🌐 网络概览", icon="🌐", disabled=True)
    st.page_link("pages/2_Device_Details.py", label="📱 设备详情", icon="📱")
    st.page_link("pages/3_Settings.py", label="⚙️ 系统设置", icon="⚙️")
    st.divider()
    st.caption("🔄 当前页面：网络概览")

show_privacy_banner()
st.title("🌐 IoT 网络全局概览")

# ========== 数据库初始化 ==========
db = None
db_path = None

try:
    current_file = os.path.abspath(__file__)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    db_path = os.path.join(project_root, 'data', 'devices.db')

    st.caption(f"数据库路径: {db_path}")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = Database(db_path)

except Exception as e:
    st.error(f"数据库初始化失败: {str(e)}")
    st.stop()

# ========== 调试工具区域 ==========
st.divider()
st.subheader("🔧 快速操作")

col1, col2 = st.columns(2)

with col1:
    if st.button("🔄 刷新页面", use_container_width=True):
        st.rerun()

with col2:
    if st.button("➕ 添加测试数据", use_container_width=True, type="primary"):
        if db is None:
            st.error("数据库未初始化")
        else:
            try:
                # 使用不会冲突的IP网段
                test_devices = [
                    {
                        'ip': '192.168.99.201',
                        'mac': 'AA:BB:CC:DD:EE:01',
                        'vendor': 'Xiaomi-Test',
                        'device_type': '测试摄像头',
                        'status': 'online',
                        'open_ports': [{'port': 80, 'service': 'http'}],
                        'services': {},
                        'risk_score': 8.5,
                        'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    },
                    {
                        'ip': '192.168.99.202',
                        'mac': 'AA:BB:CC:DD:EE:02',
                        'vendor': 'TP-Link-Test',
                        'device_type': '测试路由器',
                        'status': 'online',
                        'open_ports': [{'port': 80, 'service': 'http'}, {'port': 443, 'service': 'https'}],
                        'services': {},
                        'risk_score': 6.0,
                        'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    },
                    {
                        'ip': '192.168.99.203',
                        'mac': 'AA:BB:CC:DD:EE:03',
                        'vendor': 'Huawei-Test',
                        'device_type': '测试音箱',
                        'status': 'offline',
                        'open_ports': [],
                        'services': {},
                        'risk_score': 3.0,
                        'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                ]

                added_count = 0
                for device in test_devices:
                    result = db.add_device(device)
                    if result:
                        added_count += 1

                if added_count > 0:
                    st.success(f"✅ 成功添加 {added_count} 个测试设备！")
                    st.cache_data.clear()
                    import time

                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.warning("设备已存在或添加失败")

            except Exception as e:
                st.error(f"添加失败: {str(e)}")
                import traceback

                st.code(traceback.format_exc())

st.divider()


# ========== 数据加载 ==========
@cache_with_ttl(seconds=5)
def get_dashboard_data():
    try:
        devices = db.get_all_devices() or []
        vuln_trend = db.get_vulnerability_trend(days=7) or []
        device_types = db.get_device_types_stats() or []
        today_scans = db.get_today_scans() or []
        vulnerable_devices = db.get_vulnerable_devices() or []

        return {
            "devices": devices,
            "vuln_trend": vuln_trend,
            "device_types": device_types,
            "today_scans": today_scans,
            "vulnerable_devices": vulnerable_devices,
            "timestamp": datetime.now()
        }
    except Exception as e:
        st.error(f"获取数据失败: {e}")
        return {
            "devices": [], "vuln_trend": [], "device_types": [],
            "today_scans": [], "vulnerable_devices": [],
            "timestamp": datetime.now()
        }


with st.spinner("正在加载网络数据..."):
    data = get_dashboard_data()

if not data["devices"]:
    st.warning("⚠️ 暂无设备数据", icon="📭")
    st.info("👆 点击上方【添加测试数据】按钮")
else:
    # 网络态势
    devices = data["devices"]
    total_devices = len(devices)
    online_devices = len([d for d in devices if d.get('status') == 'online'])
    high_risk = len(data["vulnerable_devices"])
    scanned_today = len(data["today_scans"])

    online_ratio = (online_devices / total_devices * 100) if total_devices > 0 else 0

    st.subheader("网络态势感知")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("总设备数", total_devices)
    with col2:
        st.metric("在线设备", online_devices, f"{online_ratio:.1f}%" if total_devices > 0 else "N/A")
    with col3:
        st.metric("高危设备", high_risk, delta_color="inverse")
    with col4:
        st.metric("今日扫描", scanned_today)

    privacy_config = load_privacy_config()
    if privacy_config.get('enable_anonymization'):
        st.caption("🔒 提示：以下统计数据已脱敏处理")

    st.divider()

    # 图表
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("📊 设备类型分布")
        if data["device_types"]:
            try:
                df_types = pd.DataFrame(data["device_types"])
                fig_pie = px.pie(
                    df_types,
                    values='count',
                    names='device_type',
                    hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Set3
                )
                fig_pie.update_traces(textposition='inside', textinfo='percent+label')
                fig_pie.update_layout(showlegend=False, height=350)
                st.plotly_chart(fig_pie, use_container_width=True)
            except Exception as e:
                st.error(f"图表生成失败: {str(e)}")
        else:
            st.info("暂无设备类型数据", icon="📭")

    with col_right:
        st.subheader("📈 近7天漏洞发现趋势")
        vuln_trend_data = data["vuln_trend"]

        if not vuln_trend_data or len(vuln_trend_data) < 2:
            vuln_trend_data = []
            for i in range(7, 0, -1):
                date_obj = datetime.now() - timedelta(days=i)
                vuln_trend_data.append({
                    'date': date_obj.strftime('%Y-%m-%d'),
                    'count': random.randint(1, 8)
                })
            st.caption("💡 显示模拟数据")

        if vuln_trend_data:
            try:
                df_trend = pd.DataFrame(vuln_trend_data)
                df_trend['date'] = pd.to_datetime(df_trend['date'])
                df_trend = df_trend.sort_values('date')

                fig_line = px.area(
                    df_trend,
                    x='date',
                    y='count',
                    line_shape="spline",
                    color_discrete_sequence=['#FF6B6B']
                )

                fig_line.update_traces(
                    fillcolor='rgba(255, 107, 107, 0.3)',
                    line=dict(color='#FF6B6B', width=3)
                )

                fig_line.add_trace(
                    go.Scatter(
                        x=df_trend['date'],
                        y=df_trend['count'],
                        mode='markers',
                        marker=dict(size=8, color='#FF6B6B', line=dict(width=2, color='white'))
                    )
                )

                fig_line.update_layout(
                    xaxis_title="日期",
                    yaxis_title="漏洞数",
                    height=350,
                    showlegend=False,
                    xaxis=dict(
                        tickformat='%m-%d',
                        tickmode='array',
                        tickvals=df_trend['date'],
                        ticktext=[d.strftime('%m-%d') for d in df_trend['date']]
                    ),
                    hovermode='x unified'
                )

                fig_line.update_xaxes(showgrid=True, gridwidth=1, gridcolor='lightgray')
                fig_line.update_yaxes(showgrid=True, gridwidth=1, gridcolor='lightgray')

                st.plotly_chart(fig_line, use_container_width=True)

                total_vulns = df_trend['count'].sum()
                avg_vulns = df_trend['count'].mean()
                st.caption(f"📊 近7天总计: {total_vulns} 个漏洞 | 日均: {avg_vulns:.1f} 个")

            except Exception as e:
                st.error(f"图表生成失败: {str(e)}")

    st.divider()

    # 流量监控
    st.subheader("🚀 实时网络流量监控")

    traffic_stats = None
    use_simulated = False

    try:
        import requests

        resp = requests.get("http://localhost:5000/api/traffic/current", timeout=2)
        if resp.status_code == 200:
            api_data = resp.json()
            if api_data and api_data.get('download_mbps') is not None:
                traffic_stats = {
                    'download_speed_bps': api_data.get('download_mbps', 0) * 1_000_000,
                    'upload_speed_bps': api_data.get('upload_mbps', 0) * 1_000_000,
                    'total_connections': api_data.get('connections', 0),
                    'packets_sent': api_data.get('packets_sent', 0),
                    'packets_recv': api_data.get('packets_recv', 0)
                }
    except:
        pass

    if not traffic_stats:
        use_simulated = True
        traffic_stats = {
            'upload_speed_bps': random.randint(500000, 2000000),
            'download_speed_bps': random.randint(2000000, 8000000),
            'total_connections': random.randint(15, 50),
            'packets_sent': random.randint(10000, 50000),
            'packets_recv': random.randint(20000, 80000)
        }

    try:
        if use_simulated:
            st.caption("💡 显示模拟数据（Flask 服务未连接）")
        else:
            st.caption("✅ 实时数据来自 Flask 流量监控服务")

        fig_gauge = make_subplots(
            rows=1, cols=2,
            specs=[[{'type': 'indicator'}, {'type': 'indicator'}]],
            horizontal_spacing=0.1
        )

        upload_mbps = traffic_stats.get('upload_speed_bps', 0) / 1_000_000
        download_mbps = traffic_stats.get('download_speed_bps', 0) / 1_000_000

        max_upload = max(upload_mbps * 1.5, 10)
        max_download = max(download_mbps * 1.5, 50)

        fig_gauge.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=upload_mbps,
                number={'suffix': " Mbps", 'font': {'size': 24}},
                delta={'reference': upload_mbps * 0.8, 'relative': True, 'valueformat': '.0%'},
                title={'text': "⬆️ 上传速度", 'font': {'size': 16}},
                gauge={
                    'axis': {'range': [None, max_upload], 'tickwidth': 1},
                    'bar': {'color': "#36A2EB", 'thickness': 0.6},
                    'bgcolor': "white",
                    'borderwidth': 2,
                    'bordercolor': "#e0e0e0",
                    'steps': [
                        {'range': [0, max_upload * 0.3], 'color': "#e6f3ff"},
                        {'range': [max_upload * 0.3, max_upload * 0.7], 'color': "#b3d9ff"},
                        {'range': [max_upload * 0.7, max_upload], 'color': "#80bfff"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 3},
                        'thickness': 0.75,
                        'value': max_upload * 0.9
                    }
                }
            ),
            row=1, col=1
        )

        fig_gauge.add_trace(
            go.Indicator(
                mode="gauge+number+delta",
                value=download_mbps,
                number={'suffix': " Mbps", 'font': {'size': 24}},
                delta={'reference': download_mbps * 0.8, 'relative': True, 'valueformat': '.0%'},
                title={'text': "⬇️ 下载速度", 'font': {'size': 16}},
                gauge={
                    'axis': {'range': [None, max_download], 'tickwidth': 1},
                    'bar': {'color': "#4BC0C0", 'thickness': 0.6},
                    'bgcolor': "white",
                    'borderwidth': 2,
                    'bordercolor': "#e0e0e0",
                    'steps': [
                        {'range': [0, max_download * 0.3], 'color': "#e6f9f9"},
                        {'range': [max_download * 0.3, max_download * 0.7], 'color': "#b3f0f0"},
                        {'range': [max_download * 0.7, max_download], 'color': "#80e6e6"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 3},
                        'thickness': 0.75,
                        'value': max_download * 0.9
                    }
                }
            ),
            row=1, col=2
        )

        fig_gauge.update_layout(height=350)
        st.plotly_chart(fig_gauge, use_container_width=True)

        with st.expander("📊 查看详细流量数据", expanded=True):
            col_net1, col_net2, col_net3, col_net4 = st.columns(4)
            with col_net1:
                st.metric("🔗 总连接数", f"{traffic_stats.get('total_connections', 'N/A'):,}")
            with col_net2:
                st.metric("📤 发送包数", f"{traffic_stats.get('packets_sent', 0):,}")
            with col_net3:
                st.metric("📥 接收包数", f"{traffic_stats.get('packets_recv', 0):,}")
            with col_net4:
                total_mb = (traffic_stats.get('packets_sent', 0) + traffic_stats.get('packets_recv', 0)) * 0.001
                st.metric("📊 估算流量", f"{total_mb:.1f} MB")

            upload_usage = min(upload_mbps / max_upload, 1.0)
            download_usage = min(download_mbps / max_download, 1.0)

            st.progress(download_usage, text=f"⬇️ 下载带宽使用率: {download_usage * 100:.1f}%")
            st.progress(upload_usage, text=f"⬆️ 上传带宽使用率: {upload_usage * 100:.1f}%")

            if download_mbps > max_download * 0.8 or upload_mbps > max_upload * 0.8:
                st.warning("⚠️ 带宽使用率高，可能存在网络拥堵")
            else:
                st.success("✅ 网络状态良好")

    except Exception as e:
        st.warning(f"流量监控初始化失败: {str(e)}")

    st.divider()
    st.caption(f"🕒 最后更新时间: {data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")

    if st.button("🔄 立即刷新数据", type="secondary"):
        st.rerun()
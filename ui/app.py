# ui/app.py
import streamlit as st

st.set_page_config(
    page_title="IoT 安全扫描器",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 显示欢迎页，不自动跳转（让用户看到侧边栏导航）
st.title("🌐 IoT 漏洞扫描系统")
st.info("👈 请从左侧边栏选择功能页面")

st.markdown("""
### 功能模块
- **网络概览**：查看全局设备状态、流量监控、漏洞趋势
- **设备详情**：查看单个设备信息、执行深度扫描、查看漏洞
- **系统设置**：配置扫描参数、隐私设置、数据管理
""")
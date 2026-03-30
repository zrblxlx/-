import os
import jinja2
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
import matplotlib.pyplot as plt
import io
import base64
from typing import Dict
from .report_data import ReportDataCollector

class PDFReportGenerator:
    def __init__(self, template_dir: str = None):
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), 'templates')

        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        self.data_collector = ReportDataCollector()

    def generate_charts(self, stats: Dict) -> Dict[str, str]:
        """生成统计图表，返回base64编码的图片"""
        charts = {}

        # 1. 漏洞严重程度分布饼图
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = {'Critical': '#DC143C', 'High': '#FF6347',
                  'Medium': '#FFA500', 'Low': '#FFD700'}
        labels = list(stats['severity_distribution'].keys())
        sizes = list(stats['severity_distribution'].values())
        colors_list = [colors.get(l, '#808080') for l in labels]

        ax.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%',
               startangle=90, textprops={'fontsize': 10})
        ax.axis('equal')

        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        charts['severity_pie'] = base64.b64encode(buf.read()).decode('utf-8')

        return charts

    def generate(self, scan_id: str = None, output_path: str = None) -> str:
        """
        生成PDF报告
        返回生成的PDF文件路径
        """
        # 1. 收集数据
        report_data = self.data_collector.get_scan_report(scan_id)

        # 2. 生成图表
        charts = self.generate_charts(report_data['statistics'])
        report_data['charts'] = charts

        # 3. 渲染HTML
        template = self.env.get_template('report_base.html')
        html_content = template.render(**report_data)

        # 4. 转换为PDF
        font_config = FontConfiguration()
        html = HTML(string=html_content)

        # 添加自定义CSS（如果需要）
        css_path = os.path.join(os.path.dirname(__file__), 'templates', 'report.css')
        stylesheets = [CSS(filename=css_path)] if os.path.exists(css_path) else []

        if output_path is None:
            timestamp = report_data['generated_at'].replace(' ', '_').replace(':', '-')
            output_path = f"reports/IoT_Security_Report_{timestamp}.pdf"

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        html.write_pdf(output_path, stylesheets=stylesheets, font_config=font_config)

        return output_path

# 便捷函数
def generate_scan_report(scan_id: str = None, output_dir: str = "reports/") -> str:
    """对外接口：生成单次扫描的报告"""
    generator = PDFReportGenerator()
    output_path = os.path.join(output_dir, f"scan_report_{scan_id or 'latest'}.pdf")
    return generator.generate(scan_id, output_path)
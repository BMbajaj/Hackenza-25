from scapy.all import rdpcap, TCP
from collections import defaultdict
from math import pi
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import ColumnDataSource, DataTable, TableColumn
from bokeh.layouts import column
from bokeh.transform import cumsum
from bokeh.palettes import Category10
import pandas as pd

# Define your pcapng file name
pcap_file = "28-1-25-bro-laptp-20ms.pcapng"

# Read all packets using Scapy
packets = rdpcap(pcap_file)


def identify_protocol(pkt):
    """
    Custom protocol identification function.
    Checks for common protocols by examining TCP ports.
    Returns a protocol label.
    """
    if pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        # Common TLS/SSL port
        if sport == 443 or dport == 443:
            return "TLS/SSL"
        # Common HTTP ports
        if sport in (80, 8080) or dport in (80, 8080):
            return "HTTP"
        # Add more heuristics as needed.
    # Fallback: use the last layer's name
    return pkt.lastlayer().name


# Compute delta time manually and group by protocol
protocol_delta_sum = defaultdict(float)
prev_time = None
for pkt in packets:
    if prev_time is None:
        prev_time = pkt.time
        continue
    delta_time = pkt.time - prev_time
    prev_time = pkt.time
    proto = identify_protocol(pkt)
    protocol_delta_sum[proto] += delta_time

# Calculate the total delta time across all protocols
total_delta = sum(protocol_delta_sum.values())

##############################################
# 1. Bar Chart (only protocols >=5% threshold)
##############################################
# Only include protocols with sum >= 5% of total_delta.
bar_data = {
    proto: dt for proto, dt in protocol_delta_sum.items() if dt >= 0.05 * total_delta
}
bar_protocols = list(bar_data.keys())
bar_delta_sums = [bar_data[proto] for proto in bar_protocols]

bar_source = ColumnDataSource(
    data=dict(protocols=bar_protocols, delta_sums=bar_delta_sums)
)

bar_chart = figure(
    x_range=bar_protocols,
    title="Sum of Delta Time per Protocol (>=5% threshold)",
    x_axis_label="Protocol",
    y_axis_label="Sum of Delta Time (seconds)",
    height=400,
    width=800,
)
bar_chart.vbar(
    x="protocols", top="delta_sums", width=0.5, source=bar_source, color="navy"
)
bar_chart.xgrid.grid_line_color = None
bar_chart.y_range.start = 0
bar_chart.xaxis.major_label_orientation = 1

# Save bar chart
output_file("bar_chart.html")
save(bar_chart)
print("Bar chart saved as 'bar_chart.html'.")

##############################################
# 2. Data Table (all protocols, ordered)
##############################################
table_data = pd.DataFrame(
    {
        "Protocol": list(protocol_delta_sum.keys()),
        "Sum of Delta Time (s)": list(protocol_delta_sum.values()),
    }
)
table_data["Percentage (%)"] = table_data["Sum of Delta Time (s)"] / total_delta * 100

# Round to three decimal places
table_data["Sum of Delta Time (s)"] = table_data["Sum of Delta Time (s)"].round(3)
table_data["Percentage (%)"] = table_data["Percentage (%)"].round(3)

# Order by descending sum of delta time
table_data = table_data.sort_values(by="Sum of Delta Time (s)", ascending=False)
table_source = ColumnDataSource(table_data)

columns = [
    TableColumn(field="Protocol", title="Protocol"),
    TableColumn(field="Sum of Delta Time (s)", title="Sum of Delta Time (s)"),
    TableColumn(field="Percentage (%)", title="Percentage (%)"),
]
data_table = DataTable(source=table_source, columns=columns, width=500, height=280)

# Save data table in its own HTML file (wrapped in a layout)
table_layout = column(data_table)
output_file("data_table.html")
save(table_layout)
print("Data table saved as 'data_table.html'.")

##############################################
# 3. Pie Chart (all protocols, no threshold)
##############################################
pie_data = pd.DataFrame(
    {
        "protocol": list(protocol_delta_sum.keys()),
        "delta_sum": list(protocol_delta_sum.values()),
    }
)
pie_data["angle"] = pie_data["delta_sum"] / total_delta * 2 * pi
pie_data["percentage"] = pie_data["delta_sum"] / total_delta * 100

# Color coding: use Category10 palette, repeat if necessary.
num_protocols = len(pie_data)
palette = (
    Category10[10]
    if num_protocols <= 10
    else Category10[10] * ((num_protocols // 10) + 1)
)
pie_data["color"] = palette[:num_protocols]

pie_source = ColumnDataSource(pie_data)

pie_chart = figure(
    title="Percentage of Delta Time per Protocol",
    height=400,
    width=400,
    toolbar_location=None,
    tools="hover",
    tooltips="@protocol: @percentage{0.2f}%",
)
pie_chart.wedge(
    x=0,
    y=1,
    radius=0.4,
    start_angle=cumsum("angle", include_zero=True),
    end_angle=cumsum("angle"),
    line_color="white",
    fill_color="color",
    legend_field="protocol",
    source=pie_source,
)
pie_chart.axis.axis_label = None
pie_chart.axis.visible = False
pie_chart.grid.grid_line_color = None

# Save pie chart
output_file("pie_chart.html")
save(pie_chart)
print("Pie chart saved as 'pie_chart.html'.")

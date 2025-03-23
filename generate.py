import sys
import pyshark
import numpy as np
from bokeh.plotting import figure, output_file, show
from bokeh.models import (ColumnDataSource, DataTable, TableColumn, CustomJS,
                          Select, Div, HoverTool, LinearColorMapper)
from bokeh.layouts import column, row, Spacer
from bokeh.palettes import Viridis256, Category10
from bokeh.models import FactorRange

# ---------------------------
# Enhanced styling constants
# ---------------------------
PLOT_WIDTH = 800
PLOT_HEIGHT = 400
TABLE_WIDTH = 800
TABLE_HEIGHT = 400
TITLE_FONT = "Helvetica"
TITLE_FONT_SIZE = "16pt"
AXIS_LABEL_FONT_SIZE = "14pt"
GRID_LINE_COLOR = "#e5e5e5"
SPACER_WIDTH = 20
BACKGROUND_COLOR = "#f5f5f5"
BORDER_RADIUS = "10px"
TEXT_COLOR = "#333333"
HIGHLIGHT_COLOR = "#4a86e8"

# ---------------------------
# Function to create elegant CSS styling
# ---------------------------
def get_elegant_css():
    return Div(text="""
    <style>
    .elegant-data-table .bk-data-table {
        background-color: white;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        overflow: hidden;
    }
    .elegant-data-table .bk-data-table .column-header {
        background-color: #4a86e8;
        color: white;
        font-weight: 600;
        border: none;
        padding: 10px;
    }
    .elegant-data-table .bk-data-table tbody tr:nth-child(even) {
        background-color: #f9f9f9;
    }
    .elegant-data-table .bk-data-table td {
        border: none;
        border-bottom: 1px solid #eaeaea;
        padding: 8px 10px;
    }
    .bk-root .bk-btn-default {
        background-color: white;
        border: 1px solid #4a86e8;
        color: #4a86e8;
        border-radius: 4px;
        transition: all 0.3s;
    }
    .bk-root .bk-btn-default:hover {
        background-color: #4a86e8;
        color: white;
    }
    .bk-root select {
        border-radius: 4px;
        border: 1px solid #cccccc;
        padding: 8px;
        background-color: white;
    }
    .section-header {
        background-color: #4a86e8;
        color: white;
        padding: 10px 15px;
        border-radius: 5px;
        margin: 20px 0 15px 0;
        font-weight: bold;
    }
    </style>
    """, width=0, height=0)

# ---------------------------
# Helper: Create a ColumnDataSource from data
# ---------------------------
def create_source(data, keys):
    if isinstance(data, dict):
        return ColumnDataSource(data)
    if not data:
        return ColumnDataSource({key: [] for key in keys})
    converted = {key: [d.get(key, None) for d in data if isinstance(d, dict)] for key in keys}
    return ColumnDataSource(converted)

# ---------------------------
# Style a figure with elegant design elements
# ---------------------------
def style_figure(p, title):
    p.title.text = title
    p.title.text_font = TITLE_FONT
    p.title.text_font_size = TITLE_FONT_SIZE
    p.title.text_font_style = "bold"
    p.title.text_color = TEXT_COLOR
    
    p.xaxis.axis_label_text_font_size = AXIS_LABEL_FONT_SIZE
    p.yaxis.axis_label_text_font_size = AXIS_LABEL_FONT_SIZE
    p.xaxis.axis_label_text_font_style = "normal"
    p.yaxis.axis_label_text_font_style = "normal"
    p.xaxis.axis_label_text_color = TEXT_COLOR
    p.yaxis.axis_label_text_color = TEXT_COLOR
    
    p.xgrid.grid_line_color = GRID_LINE_COLOR
    p.ygrid.grid_line_color = GRID_LINE_COLOR
    p.xgrid.grid_line_dash = [6, 4]
    p.ygrid.grid_line_dash = [6, 4]
    
    p.background_fill_color = BACKGROUND_COLOR
    p.border_fill_color = "white"
    p.outline_line_color = None
    
    # Enhanced hover tool with more detailed tooltips
    tooltips = [("Time", "@time{0.000}"), ("Value", "@$name{0.000}")]
    if "src" in p.renderers[0].data_source.data if p.renderers else {}:
        tooltips.extend([("Source", "@src"), ("Destination", "@dst")])
    if "length" in p.renderers[0].data_source.data if p.renderers else {}:
        tooltips.append(("Length", "@length"))
    p.add_tools(HoverTool(tooltips=tooltips))
    
    return p
# ---------------------------
# Data Extraction: Extract ACK_RTT values and IP packet times.
# ---------------------------
# Ensure a file is provided as a command-line argument
if len(sys.argv) < 2:
    print("Usage: python generate.py <pcapng_file>")
    sys.exit(1)

pcap_file = sys.argv[1]

print(pcap_file)

ack_rtt_list = []
ip_times = []

capture = pyshark.FileCapture(pcap_file, display_filter="ip")
for packet in capture:
    try:
        if (hasattr(packet, 'ip') and hasattr(packet, 'tcp') and 
            hasattr(packet.tcp, 'analysis_ack_rtt')):
            ts = float(packet.sniff_timestamp)
            ack_rtt = float(packet.tcp.analysis_ack_rtt)
            src = packet.ip.src
            dst = packet.ip.dst
            length = int(packet.frame_info.len) if hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'len') else None
            ack_rtt_list.append({"time": ts, "ack_rtt": ack_rtt, "src": src, "dst": dst, "length": length})
        if hasattr(packet, 'ip'):
            ts = float(packet.sniff_timestamp)
            src = packet.ip.src
            dst = packet.ip.dst
            ip_times.append({"time": ts, "src": src, "dst": dst})
    except Exception:
        continue
capture.close()

# ---------------------------
# Group data by conversations and sources
# ---------------------------
def group_by_conversation(data):
    groups = {}
    for d in data:
        if not isinstance(d, dict):
            continue
        key = (d["src"], d["dst"])
        groups.setdefault(key, []).append(d)
    return groups

def group_by_source(data):
    groups = {}
    for d in data:
        if not isinstance(d, dict):
            continue
        key = d["src"]
        groups.setdefault(key, []).append(d)
    return groups

def compute_delays_by_conversation(ip_data):
    conv = {}
    for d in ip_data:
        if not isinstance(d, dict):
            continue
        key = (d["src"], d["dst"])
        conv.setdefault(key, []).append(d["time"])
    conv_delays = {}
    for key, times in conv.items():
        times.sort()
        delays = []
        delay_times = []
        for i in range(1, len(times)):
            delays.append(times[i] - times[i-1])
            delay_times.append(times[i])
        conv_delays[key] = {"times": delay_times, "delays": delays}
    return conv_delays

conv_delays = compute_delays_by_conversation(ip_times)

def group_delays_by_source(conv_delays):
    groups = {}
    for (src, dst), data in conv_delays.items():
        groups.setdefault(src, []).extend([{"time": t, "delay": d, "dst": dst} for t, d in zip(data["times"], data["delays"])])
    return groups

delays_by_source = group_delays_by_source(conv_delays)

# ---------------------------
# Create correlation plot for outliers
# ---------------------------
def add_correlation_plot(layout, ack_items, group_name):
    ack_vals = [d["ack_rtt"] for d in ack_items if d.get("ack_rtt") is not None]
    if not ack_vals:
        return layout
    
    arr = np.array(ack_vals)
    mean_val = np.mean(arr)
    std_val = np.std(arr)
    threshold = mean_val + 2 * std_val
    outlier_items = [d for d in ack_items if d["ack_rtt"] > threshold and d.get("length") is not None]
    
    if not outlier_items:
        return layout
        
    p_corr = figure(x_axis_label="Packet Length", y_axis_label="ACK_RTT (sec)",
                    width=PLOT_WIDTH, height=PLOT_HEIGHT)
    p_corr = style_figure(p_corr, f"Length vs ACK_RTT Outliers - {group_name}")
    
    outlier_minimal = [d for d in outlier_items if d.get("length") == 54]
    outlier_regular = [d for d in outlier_items if d.get("length") != 54]
    
    if outlier_minimal:
        src_min = create_source(outlier_minimal, ["time", "ack_rtt", "length", "src", "dst"])
        p_corr.scatter("length", "ack_rtt", source=src_min, size=10, color="#e74c3c", alpha=0.8, legend_label="Minimal ACK")
    
    if outlier_regular:
        src_reg = create_source(outlier_regular, ["time", "ack_rtt", "length", "src", "dst"])
        p_corr.scatter("length", "ack_rtt", source=src_reg, size=10, color="#9b59b6", alpha=0.8, legend_label="Other")
    
    p_corr.legend.location = "top_left"
    p_corr.legend.border_line_color = None
    p_corr.legend.background_fill_alpha = 0.7
    
    all_outliers = outlier_minimal + outlier_regular
    src_corr = create_source(all_outliers, ["time", "ack_rtt", "length", "src", "dst"])
    columns_corr = [
        TableColumn(field="time", title="Time (Epoch)"),
        TableColumn(field="ack_rtt", title="ACK_RTT (sec)"),
        TableColumn(field="length", title="Length"),
        TableColumn(field="src", title="Source"),
        TableColumn(field="dst", title="Destination")
    ]
    table_corr = DataTable(source=src_corr, columns=columns_corr, width=TABLE_WIDTH, 
                           height=TABLE_HEIGHT, css_classes=["elegant-data-table"])
    
    header = Div(text=f'<div class="section-header">Outlier Correlation Analysis</div>')
    return column(layout, header, row(p_corr, Spacer(width=SPACER_WIDTH), table_corr))

# ---------------------------
# Build conversation view layout
# ---------------------------
def build_conversation_layout(ack_groups, delay_groups):
    layouts = []
    conv_names = []
    
    for key, ack_items in ack_groups.items():
        name = f"{key[0]} → {key[1]}"
        conv_names.append(name)
        ack_items.sort(key=lambda d: d["time"])
        
        # ACK RTT plot
        times_ack = [d["time"] for d in ack_items]
        ack_vals = [d["ack_rtt"] for d in ack_items]
        lengths_ack = [d.get("length") for d in ack_items]
        
        ack_dict = {"time": times_ack, "ack_rtt": ack_vals, "length": lengths_ack}
        ack_source = create_source(ack_dict, ["time", "ack_rtt", "length"])
        
        p_ack = figure(x_axis_label="Time (Epoch)", y_axis_label="ACK_RTT (sec)",
                       width=PLOT_WIDTH, height=PLOT_HEIGHT)
        p_ack = style_figure(p_ack, f"ACK Round-Trip Time - {name}")
        p_ack.scatter("time", "ack_rtt", name="ack_rtt", source=ack_source, size=8, 
                      color=HIGHLIGHT_COLOR, alpha=0.7)
        
        columns_ack = [
            TableColumn(field="time", title="Time (Epoch)"),
            TableColumn(field="ack_rtt", title="ACK_RTT (sec)")
        ]
        table_ack = DataTable(source=ack_source, columns=columns_ack, width=TABLE_WIDTH,
                              height=TABLE_HEIGHT, css_classes=["elegant-data-table"])
        
        ack_header = Div(text=f'<div class="section-header">ACK RTT Analysis</div>')
        ack_layout = column(ack_header, row(p_ack, Spacer(width=SPACER_WIDTH), table_ack))
        
        # Delay plot if available
        if key in delay_groups:
            delay_data = delay_groups[key]
            times_delay = delay_data["times"]
            delay_vals = delay_data["delays"]
            
            delay_dict = {"time": times_delay, "delay": delay_vals}
            delay_source = create_source(delay_dict, ["time", "delay"])
            
            p_delay = figure(x_axis_label="Time (Epoch)", y_axis_label="Delay (sec)",
                           width=PLOT_WIDTH, height=PLOT_HEIGHT)
            p_delay = style_figure(p_delay, f"Packet Delay - {name}")
            p_delay.scatter("time", "delay", name="delay", source=delay_source, size=8, 
                          color="#2ecc71", alpha=0.7)
            
            columns_delay = [
                TableColumn(field="time", title="Time (Epoch)"),
                TableColumn(field="delay", title="Delay (sec)")
            ]
            table_delay = DataTable(source=delay_source, columns=columns_delay, width=TABLE_WIDTH,
                                  height=TABLE_HEIGHT, css_classes=["elegant-data-table"])
            
            delay_header = Div(text=f'<div class="section-header">Packet Delay Analysis</div>')
            delay_layout = column(delay_header, row(p_delay, Spacer(width=SPACER_WIDTH), table_delay))
            full_layout = column(ack_layout, delay_layout)
        else:
            full_layout = ack_layout
        
        # Add correlation plot
        full_layout = add_correlation_plot(full_layout, ack_items, name)
        full_layout.tags = [name]
        full_layout.visible = False
        layouts.append(full_layout)
    
    if not layouts:
        return column(Div(text="No conversation data available."))
    
    layouts[0].visible = True
    container = column(*layouts)
    options = sorted(list(set(conv_names)))
    
    select = Select(title="Select Conversation", value=options[0], options=options, width=300)
    callback = CustomJS(args=dict(container=container), code="""
        var selected = cb_obj.value;
        for (var i = 0; i < container.children.length; i++){
            var name = container.children[i].tags[0];
            container.children[i].visible = (name === selected);
        }
    """)
    select.js_on_change('value', callback)
    
    title = Div(text="<h2 style='color:#4a86e8;margin-bottom:5px'>Conversation Analysis</h2>")
    return column(get_elegant_css(), title, select, container)

# ---------------------------
# Build source IP view layout
# ---------------------------
def build_source_layout(ack_data, delay_data):
    layouts = []
    source_names = []
    ack_src_groups = group_by_source(ack_data)
    delay_src_groups = group_by_source(delay_data)
    
    for src, ack_items in ack_src_groups.items():
        source_names.append(src)
        dest_groups = {}
        for d in ack_items:
            dest_groups.setdefault(d["dst"], []).append(d)
        
        p_ack = figure(x_axis_label="Time (Epoch)", y_axis_label="ACK_RTT (sec)",
                     width=PLOT_WIDTH, height=PLOT_HEIGHT)
        p_ack = style_figure(p_ack, f"Source IP Analysis - {src}")
        
        table_rows = []
        palette = Category10[10]
        for idx, (dst, items) in enumerate(dest_groups.items()):
            items.sort(key=lambda d: d["time"])
            times = [d["time"] for d in items]
            ack_vals = [d["ack_rtt"] for d in items]
            lengths = [d.get("length") for d in items]
            color = palette[idx % len(palette)]
            
            source_dst = create_source({"time": times, "ack_rtt": ack_vals, "length": lengths}, 
                                      ["time", "ack_rtt", "length"])
            p_ack.scatter("time", "ack_rtt", name="ack_rtt", source=source_dst, size=8, 
                        color=color, alpha=0.7, legend_label=f"to {dst}")
            
            table_rows.extend([{"time": t, "ack_rtt": a, "dst": dst, "length": l} 
                             for t, a, l in zip(times, ack_vals, lengths)])
        
        p_ack.legend.location = "top_left"
        p_ack.legend.background_fill_alpha = 0.7
        p_ack.legend.border_line_color = None
        
        ack_header = Div(text=f'<div class="section-header">ACK RTT by Destination</div>')
        table_ack = DataTable(
            source=create_source(table_rows, ["time", "ack_rtt", "dst", "length"]),
            columns=[
                TableColumn(field="time", title="Time (Epoch)"),
                TableColumn(field="ack_rtt", title="ACK_RTT (sec)"),
                TableColumn(field="dst", title="Destination"),
                TableColumn(field="length", title="Length")
            ],
            width=TABLE_WIDTH, height=TABLE_HEIGHT, css_classes=["elegant-data-table"]
        )
        
        ack_layout = column(ack_header, row(p_ack, Spacer(width=SPACER_WIDTH), table_ack))
        
        # Create delay analysis if available
        if src in delay_src_groups:
            delay_items = delay_src_groups[src]
            dest_delay_groups = {}
            for d in delay_items:
                dest_delay_groups.setdefault(d["dst"], []).append(d)
            
            p_delay = figure(x_axis_label="Time (Epoch)", y_axis_label="Delay (sec)",
                           width=PLOT_WIDTH, height=PLOT_HEIGHT)
            p_delay = style_figure(p_delay, f"Packet Delay Analysis - {src}")
            
            table_delay_rows = []
            for idx, (dst, items) in enumerate(dest_delay_groups.items()):
                items.sort(key=lambda d: d["time"])
                times = [d["time"] for d in items]
                delay_vals = [d["delay"] for d in items]
                color = palette[idx % len(palette)]
                
                src_delay = create_source({"time": times, "delay": delay_vals, "dst": [dst]*len(times)}, 
                                        ["time", "delay", "dst"])
                p_delay.scatter("time", "delay", name="delay", source=src_delay, size=8, 
                              color=color, alpha=0.7, legend_label=f"to {dst}")
                
                table_delay_rows.extend([{"time": t, "delay": d_val, "dst": dst} 
                                       for t, d_val in zip(times, delay_vals)])
            
            p_delay.legend.location = "top_left"
            p_delay.legend.background_fill_alpha = 0.7
            p_delay.legend.border_line_color = None
            
            delay_header = Div(text=f'<div class="section-header">Packet Delays by Destination</div>')
            table_delay = DataTable(
                source=create_source(table_delay_rows, ["time", "delay", "dst"]),
                columns=[
                    TableColumn(field="time", title="Time (Epoch)"),
                    TableColumn(field="delay", title="Delay (sec)"),
                    TableColumn(field="dst", title="Destination")
                ],
                width=TABLE_WIDTH, height=TABLE_HEIGHT, css_classes=["elegant-data-table"]
            )
            
            delay_layout = column(delay_header, row(p_delay, Spacer(width=SPACER_WIDTH), table_delay))
            full_layout = column(ack_layout, delay_layout)
        else:
            full_layout = ack_layout
        
        # Add correlation plot
        full_layout = add_correlation_plot(full_layout, ack_items, src)
        full_layout.tags = [src]
        full_layout.visible = False
        layouts.append(full_layout)
    
    if not layouts:
        return column(Div(text="No source data available."))
    
    layouts[0].visible = True
    container = column(*layouts)
    options = sorted(list(set(source_names)))
    
    select = Select(title="Select Source IP", value=options[0], options=options, width=300)
    callback = CustomJS(args=dict(container=container), code="""
        var selected = cb_obj.value;
        for (var i = 0; i < container.children.length; i++){
            var name = container.children[i].tags[0];
            container.children[i].visible = (name === selected);
        }
    """)
    select.js_on_change('value', callback)
    
    title = Div(text="<h2 style='color:#4a86e8;margin-bottom:5px'>Source IP Analysis</h2>")
    return column(get_elegant_css(), title, select, container)

# ---------------------------
# Build overview analysis with bar plots and correlation
# ---------------------------
def compute_percentage_outliers(data, value_field):
    groups = group_by_source(data)
    return {src: (np.sum(np.array([item[value_field] for item in items]) > 
              (np.mean([item[value_field] for item in items]) + 
               2 * np.std([item[value_field] for item in items]))) / 
              len(items) * 100) if items else 0 
            for src, items in groups.items()}

ack_out_percent = compute_percentage_outliers(ack_rtt_list, "ack_rtt")
delay_out_percent = {}
delay_groups_all = {}

for (src, dst), d in conv_delays.items():
    delay_groups_all.setdefault(src, []).extend(d["delays"])

for src, delays in delay_groups_all.items():
    if delays:
        arr = np.array(delays)
        mean_val = np.mean(arr)
        std_val = np.std(arr)
        threshold = mean_val + 2 * std_val
        count_out = np.sum(arr > threshold)
        delay_out_percent[src] = (count_out / len(arr)) * 100
    else:
        delay_out_percent[src] = 0

def build_bar_chart(percentages, title, y_label, color):
    sources = list(percentages.keys())
    percentages_list = [percentages[src] for src in sources]
    
    p = figure(x_range=FactorRange(*sources), x_axis_label="Source IP", 
               y_axis_label=y_label, width=PLOT_WIDTH, height=PLOT_HEIGHT)
    p = style_figure(p, title)
    
    source = ColumnDataSource(data={"src": sources, "percentage": percentages_list})
    p.vbar(x="src", top="percentage", width=0.5, source=source, 
           fill_color=color, line_color=None, alpha=0.8)
    
    p.add_tools(HoverTool(tooltips=[
        ("Source", "@src"),
        ("Percentage", "@percentage{0.00}%")
    ]))
    
    return p, source

ack_header = Div(text=f'<div class="section-header">Outlier Analysis - ACK RTT</div>')
p_ack_bar, ack_bar_source = build_bar_chart(
    ack_out_percent, 
    "Percentage of ACK_RTT Outliers by Source IP",
    "Percentage (%)", 
    HIGHLIGHT_COLOR
)

delay_header = Div(text=f'<div class="section-header">Outlier Analysis - Packet Delay</div>')
p_delay_bar, delay_bar_source = build_bar_chart(
    delay_out_percent, 
    "Percentage of Delay Outliers by Source IP",
    "Percentage (%)", 
    "#2ecc71"
)

ack_table_bar = DataTable(
    source=ack_bar_source,
    columns=[
        TableColumn(field="src", title="Source IP"),
        TableColumn(field="percentage", title="Outlier %")
    ],
    width=TABLE_WIDTH, height=TABLE_HEIGHT, css_classes=["elegant-data-table"]
)

delay_table_bar = DataTable(
    source=delay_bar_source,
    columns=[
        TableColumn(field="src", title="Source IP"),
        TableColumn(field="percentage", title="Outlier %")
    ],
    width=TABLE_WIDTH, height=TABLE_HEIGHT, css_classes=["elegant-data-table"]
)

# Build overall correlation analysis
outlier_items = []
for src, group in group_by_source(ack_rtt_list).items():
    if group:
        arr = np.array([d["ack_rtt"] for d in group if d.get("ack_rtt") is not None])
        if arr.size:
            mean_val = np.mean(arr)
            std_val = np.std(arr)
            threshold = mean_val + 2 * std_val
            outlier_items.extend([d for d in group if d["ack_rtt"] > threshold and d.get("length") is not None])

corr_header = Div(text=f'<div class="section-header">Overall Correlation Analysis</div>')
p_all_corr = figure(x_axis_label="Packet Length", y_axis_label="ACK_RTT (sec)",
                   width=PLOT_WIDTH, height=PLOT_HEIGHT)
p_all_corr = style_figure(p_all_corr, "Overall Correlation: Packet Length vs ACK_RTT")

all_corr_source = create_source(outlier_items, ["time", "ack_rtt", "length", "src", "dst"])
p_all_corr.scatter("length", "ack_rtt", name="ack_rtt", source=all_corr_source, 
                  size=10, color="#9b59b6", alpha=0.8)

table_all_corr = DataTable(
    source=all_corr_source,
    columns=[
        TableColumn(field="time", title="Time (Epoch)"),
        TableColumn(field="ack_rtt", title="ACK_RTT (sec)"),
        TableColumn(field="length", title="Length"),
        TableColumn(field="src", title="Source IP"),
        TableColumn(field="dst", title="Destination IP")
    ],
    width=TABLE_WIDTH, height=TABLE_HEIGHT, css_classes=["elegant-data-table"]
)

# Generate outputs
ack_conv_groups = group_by_conversation(ack_rtt_list)
conversation_layout = build_conversation_layout(ack_conv_groups, conv_delays)
output_file("plot1.html")
show(conversation_layout)

source_layout = build_source_layout(ack_rtt_list, delays_by_source)
output_file("plot2.html")
show(source_layout)

title = Div(text="<h2 style='color:#4a86e8;margin-bottom:5px'>Network Traffic Overview</h2>")
summary_layout = column(
    get_elegant_css(),
    title,
    row(column(ack_header, p_ack_bar), column(delay_header, p_delay_bar)),
    row(ack_table_bar, Spacer(width=SPACER_WIDTH), delay_table_bar),
    corr_header,
    # Changed from row followed by row to a single row with all elements
    row(p_all_corr, Spacer(width=SPACER_WIDTH), table_all_corr)
)
output_file("plot3.html")
show(summary_layout)

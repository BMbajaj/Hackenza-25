import pyshark
import numpy as np
from bokeh.plotting import figure, output_file, show
from bokeh.models import (ColumnDataSource, DataTable, TableColumn, CustomJS,
                          Select, Div)
from bokeh.layouts import column, row
from bokeh.palettes import Category10
from bokeh.models import HoverTool
from bokeh.transform import dodge
from bokeh.models import FactorRange

# -----------------------------------------------------------------------------
# Helper: Create a ColumnDataSource from either a dict or a list of dicts.
# -----------------------------------------------------------------------------
def create_source(data, keys):
    if isinstance(data, dict):
        return ColumnDataSource(data)
    if not data:
        return ColumnDataSource({key: [] for key in keys})
    converted = {key: [d.get(key, None) for d in data if isinstance(d, dict)] for key in keys}
    return ColumnDataSource(converted)

# -----------------------------------------------------------------------------
# Data Extraction: Extract ACK_RTT values (with packet length) and IP packet times.
# -----------------------------------------------------------------------------
pcap_file = "28-1-25-bro-rpi-60ms.pcapng"

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
# (No filtering is applied; all ACK packets are included.)

# -----------------------------------------------------------------------------
# Grouping Functions
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Helper: Add a correlation plot (Length vs ACK_RTT for outlier packets)
# This plot is appended at the end of each HTML output.
# Outlier packets are defined using the threshold (mean + 2*std).
# In the correlation plot, outlier packets with length==54 are colored magenta,
# and all other outlier packets are colored purple.
# -----------------------------------------------------------------------------
def add_correlation_plot(layout, ack_items, group_name):
    ack_vals = [d["ack_rtt"] for d in ack_items if d.get("ack_rtt") is not None]
    if not ack_vals:
        corr_layout = column(Div(text="No ACK_RTT data for correlation."))
    else:
        arr = np.array(ack_vals)
        mean_val = np.mean(arr)
        std_val = np.std(arr)
        threshold = mean_val + 2 * std_val
        outlier_items = [d for d in ack_items if d["ack_rtt"] > threshold and d.get("length") is not None]
        if outlier_items:
            outlier_minimal = [d for d in outlier_items if d.get("length") == 54]
            outlier_regular = [d for d in outlier_items if d.get("length") != 54]
            p_corr = figure(title=f"Correlation (Outliers) for {group_name}: Length vs ACK_RTT",
                            x_axis_label="Packet Length", y_axis_label="ACK_RTT (sec)",
                            width=800, height=400)
            if outlier_minimal:
                src_min = create_source(outlier_minimal, ["time", "ack_rtt", "length", "src", "dst"])
                p_corr.scatter("length", "ack_rtt", source=src_min, size=8, color="magenta", alpha=0.7, legend_label="Minimal ACK Outliers")
            if outlier_regular:
                src_reg = create_source(outlier_regular, ["time", "ack_rtt", "length", "src", "dst"])
                p_corr.scatter("length", "ack_rtt", source=src_reg, size=8, color="purple", alpha=0.7, legend_label="Other Outliers")
            p_corr.legend.location = "top_left"
            # Combine all outlier items and include src and dst in the table.
            all_outliers = outlier_minimal + outlier_regular
            src_corr = create_source(all_outliers, ["time", "ack_rtt", "length", "src", "dst"])
            columns_corr = [TableColumn(field="time", title="Time (Epoch)"),
                            TableColumn(field="ack_rtt", title="ACK_RTT (sec)"),
                            TableColumn(field="length", title="Length"),
                            TableColumn(field="src", title="Source IP"),
                            TableColumn(field="dst", title="Destination IP")]
            table_corr = DataTable(source=src_corr, columns=columns_corr, width=400, height=300)
            corr_layout = column(p_corr, table_corr)
        else:
            corr_layout = column(Div(text="No outlier correlation data available."))
    if not corr_layout.children:
        corr_layout = column(Div(text="No correlation data available."))
    return column(layout, Div(text="<hr>Correlation Plot:"), corr_layout)

# -----------------------------------------------------------------------------
# HTML 1: Group by Conversation (Drop-down)
# -----------------------------------------------------------------------------
def build_conversation_layout(ack_groups, delay_groups):
    layouts = []
    conv_names = []
    for key, ack_items in ack_groups.items():
        name = f"{key[0]} -> {key[1]}"
        conv_names.append(name)
        ack_items.sort(key=lambda d: d["time"])
        times_ack = [d["time"] for d in ack_items]
        ack_vals = [d["ack_rtt"] for d in ack_items]
        lengths_ack = [d.get("length") for d in ack_items]
        if ack_vals:
            arr = np.array(ack_vals)
            mean_val = np.mean(arr)
            std_val = np.std(arr)
            threshold = mean_val + 2 * std_val
            out_idx = [i for i, v in enumerate(ack_vals) if v > threshold]
        else:
            out_idx = []
        # In the main ACK_RTT plot, plot all points normally.
        ack_dict = {"time": times_ack, "ack_rtt": ack_vals, "length": lengths_ack}
        ack_source = create_source(ack_dict, ["time", "ack_rtt", "length"])
        p_ack = figure(title=f"ACK_RTT for {name}",
                       x_axis_label="Time (Epoch)", y_axis_label="ACK_RTT (sec)",
                       width=800, height=400)
        p_ack.scatter("time", "ack_rtt", source=ack_source, size=6, color="blue", alpha=0.5, legend_label="ACK_RTT")
        p_ack.legend.location = "top_left"
        columns_ack = [TableColumn(field="time", title="Time (Epoch)"),
                       TableColumn(field="ack_rtt", title="ACK_RTT (sec)")]
        table_ack = DataTable(source=ack_source, columns=columns_ack, width=400, height=300)
        ack_layout = column(p_ack, table_ack)
        
        if key in delay_groups:
            delay_data = delay_groups[key]
            times_delay = delay_data["times"]
            delay_vals = delay_data["delays"]
            if delay_vals:
                arr_d = np.array(delay_vals)
                mean_d = np.mean(arr_d)
                std_d = np.std(arr_d)
                threshold_d = mean_d + 2 * std_d
                out_idx_d = [i for i, v in enumerate(delay_vals) if v > threshold_d]
            else:
                out_idx_d = []
            delay_dict = {"time": times_delay, "delay": delay_vals}
            delay_source = create_source(delay_dict, ["time", "delay"])
            p_delay = figure(title=f"Delay for {name}",
                             x_axis_label="Time (Epoch)", y_axis_label="Delay (sec)",
                             width=800, height=400)
            p_delay.scatter("time", "delay", source=delay_source, size=6, color="green", alpha=0.5, legend_label="Delay")
            p_delay.legend.location = "top_left"
            columns_delay = [TableColumn(field="time", title="Time (Epoch)"),
                             TableColumn(field="delay", title="Delay (sec)")]
            table_delay = DataTable(source=delay_source, columns=columns_delay, width=400, height=300)
            delay_layout = column(p_delay, table_delay)
        else:
            delay_layout = column()
        full_layout = column(ack_layout, delay_layout)
        full_layout = add_correlation_plot(full_layout, ack_items, name)
        full_layout.tags = [name]
        full_layout.visible = False
        layouts.append(full_layout)
    if not layouts:
        return column(Div(text="No conversation data available."))
    layouts[0].visible = True
    container = column(*layouts)
    options = sorted(list(set(conv_names)))
    select = Select(title="Select Conversation", value=options[0], options=options)
    callback = CustomJS(args=dict(container=container), code="""
        var selected = cb_obj.value;
        for (var i = 0; i < container.children.length; i++){
            var name = container.children[i].tags[0];
            container.children[i].visible = (name === selected);
        }
    """)
    select.js_on_change('value', callback)
    return column(Div(text="<b>Remove minimal ACK packets:</b> Disabled"), select, container)

ack_conv_groups = group_by_conversation(ack_rtt_list)
conversation_layout = build_conversation_layout(ack_conv_groups, conv_delays)
output_file("conversation_ack_rtt.html")
show(conversation_layout)

# -----------------------------------------------------------------------------
# HTML 2: Group by Source IP (Drop-down with different colors per destination)
# -----------------------------------------------------------------------------
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
        p_ack = figure(title=f"ACK_RTT for Source {src}",
                       x_axis_label="Time (Epoch)", y_axis_label="ACK_RTT (sec)",
                       width=800, height=400)
        table_rows = []
        palette = Category10[10]
        idx = 0
        for dst, items in dest_groups.items():
            items.sort(key=lambda d: d["time"])
            times = [d["time"] for d in items]
            ack_vals = [d["ack_rtt"] for d in items]
            lengths = [d.get("length") for d in items]
            color = palette[idx % len(palette)]
            idx += 1
            source_dst = create_source([{"time": t, "ack_rtt": a, "length": l} for t, a, l in zip(times, ack_vals, lengths)], ["time", "ack_rtt", "length"])
            p_ack.scatter("time", "ack_rtt", source=source_dst, size=6, color=color, alpha=0.5, legend_label=f"dst {dst}")
            table_rows.extend([{"time": t, "ack_rtt": a, "dst": dst, "length": l} for t, a, l in zip(times, ack_vals, lengths)])
        p_ack.legend.location = "top_left"
        table_ack = DataTable(source=create_source(table_rows, ["time", "ack_rtt", "dst", "length"]),
                              columns=[TableColumn(field="time", title="Time (Epoch)"),
                                       TableColumn(field="ack_rtt", title="ACK_RTT (sec)"),
                                       TableColumn(field="dst", title="Destination"),
                                       TableColumn(field="length", title="Length")],
                              width=400, height=300)
        ack_layout = column(p_ack, table_ack)
        
        if src in delay_src_groups:
            delay_items = delay_src_groups[src]
            dest_delay_groups = {}
            for d in delay_items:
                dest_delay_groups.setdefault(d["dst"], []).append(d)
            p_delay = figure(title=f"Delay for Source {src}",
                             x_axis_label="Time (Epoch)", y_axis_label="Delay (sec)",
                             width=800, height=400)
            table_delay_rows = []
            idx = 0
            for dst, items in dest_delay_groups.items():
                items.sort(key=lambda d: d["time"])
                times = [d["time"] for d in items]
                delay_vals = [d["delay"] for d in items]
                color = palette[idx % len(palette)]
                idx += 1
                src_delay = create_source([{"time": t, "delay": d_val, "dst": dst} for t, d_val in zip(times, delay_vals)], ["time", "delay", "dst"])
                p_delay.scatter("time", "delay", source=src_delay, size=6, color=color, alpha=0.5, legend_label=f"dst {dst}")
                table_delay_rows.extend([{"time": t, "delay": d_val, "dst": dst} for t, d_val in zip(times, delay_vals)])
            p_delay.legend.location = "top_left"
            table_delay = DataTable(source=create_source(table_delay_rows, ["time", "delay", "dst"]),
                                    columns=[TableColumn(field="time", title="Time (Epoch)"),
                                             TableColumn(field="delay", title="Delay (sec)"),
                                             TableColumn(field="dst", title="Destination")],
                                    width=400, height=300)
            delay_layout = column(p_delay, table_delay)
        else:
            delay_layout = column()
        full_layout = column(ack_layout, delay_layout)
        full_layout = add_correlation_plot(full_layout, ack_items, src)
        full_layout.tags = [src]
        full_layout.visible = False
        layouts.append(full_layout)
    if not layouts:
        return column(Div(text="No source data available."))
    layouts[0].visible = True
    container = column(*layouts)
    options = sorted(list(set(source_names)))
    select = Select(title="Select Source IP", value=options[0], options=options)
    callback = CustomJS(args=dict(container=container), code="""
        var selected = cb_obj.value;
        for (var i = 0; i < container.children.length; i++){
            var name = container.children[i].tags[0];
            container.children[i].visible = (name === selected);
        }
    """)
    select.js_on_change('value', callback)
    return column(Div(text="<b>Remove minimal ACK packets:</b> Disabled"), select, container)

source_layout = build_source_layout(ack_rtt_list, delays_by_source)
output_file("source_ack_rtt.html")
show(source_layout)

# -----------------------------------------------------------------------------
# HTML 3: All Packets – Bar Plots of Percentage Outliers by Source IP, plus Overall Correlation Plot.
# -----------------------------------------------------------------------------
def compute_percentage_outliers(data, value_field):
    groups = group_by_source(data)
    percentages = {}
    for src, items in groups.items():
        values = [item[value_field] for item in items if isinstance(item, dict)]
        if not values:
            percentages[src] = 0
        else:
            arr = np.array(values)
            mean_val = np.mean(arr)
            std_val = np.std(arr)
            threshold = mean_val + 2 * std_val
            count_out = np.sum(arr > threshold)
            percentages[src] = (count_out / len(arr)) * 100
    return percentages

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
    data = {"src": sources, "percentage": percentages_list}
    src_data = ColumnDataSource(data=data)
    p = figure(x_range=FactorRange(*sources), title=title,
               x_axis_label="Source IP", y_axis_label=y_label,
               width=800, height=400)
    p.vbar(x="src", top="percentage", width=0.5, source=src_data, color=color)
    p.add_tools(HoverTool(tooltips=[("Source", "@src"), ("Percentage", "@percentage{0.0}%")]))
    return p

p_ack_bar = build_bar_chart(ack_out_percent, "Percentage Outliers in ACK_RTT by Source IP",
                            "Percentage (%)", "blue")
p_delay_bar = build_bar_chart(delay_out_percent, "Percentage Outliers in Delay by Source IP",
                              "Percentage (%)", "green")

table_columns = [
    TableColumn(field="src", title="Source IP"),
    TableColumn(field="percentage", title="Outlier Percentage (%)")
]
ack_table_bar = DataTable(source=ColumnDataSource({"src": list(ack_out_percent.keys()), "percentage": list(ack_out_percent.values())}),
                      columns=table_columns, width=400, height=300)
delay_table_bar = DataTable(source=ColumnDataSource({"src": list(delay_out_percent.keys()), "percentage": list(delay_out_percent.values())}),
                        columns=table_columns, width=400, height=300)

# Overall correlation: include src and dst in the table.
all_corr_items = []
for src, group in group_by_source(ack_rtt_list).items():
    if group:
        arr = np.array([d["ack_rtt"] for d in group if d.get("ack_rtt") is not None])
        if arr.size:
            mean_val = np.mean(arr)
            std_val = np.std(arr)
            threshold = mean_val + 2 * std_val
            for d in group:
                if d["ack_rtt"] > threshold and d.get("length") is not None:
                    all_corr_items.append(d)
all_corr_source = create_source(all_corr_items, ["time", "ack_rtt", "length", "src", "dst"])
p_all_corr = figure(title="Overall Correlation: Packet Length vs ACK_RTT (Outliers)",
                    x_axis_label="Packet Length", y_axis_label="ACK_RTT (sec)",
                    width=800, height=400)
p_all_corr.scatter("length", "ack_rtt", source=all_corr_source, size=8, color="purple", alpha=0.7, legend_label="Outliers")
p_all_corr.legend.location = "top_left"
columns_all_corr = [TableColumn(field="time", title="Time (Epoch)"),
                    TableColumn(field="ack_rtt", title="ACK_RTT (sec)"),
                    TableColumn(field="length", title="Length"),
                    TableColumn(field="src", title="Source IP"),
                    TableColumn(field="dst", title="Destination IP")]
table_all_corr = DataTable(source=all_corr_source, columns=columns_all_corr, width=400, height=300)
layout_all_corr = column(p_all_corr, table_all_corr)

layout_ack_bar = column(p_ack_bar, ack_table_bar)
layout_delay_bar = column(p_delay_bar, delay_table_bar)
layout_all = column(layout_ack_bar, layout_delay_bar, Div(text="<hr>Overall Correlation:"), layout_all_corr)

output_file("all_ips_outliers.html")
show(layout_all)


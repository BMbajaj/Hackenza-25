import pyshark
import pandas as pd
import sys
from bokeh.plotting import figure, show
from bokeh.io import output_file
from bokeh.layouts import column
from bokeh.models import (
    ColumnDataSource, DataTable, TableColumn, HoverTool
)
from collections import defaultdict
from bokeh.themes import built_in_themes
from bokeh.io import curdoc

# Apply dark mode theme - add this before creating any figures
curdoc().theme = built_in_themes["dark_minimal"]
def analyze_pcapng(file_path):
    """
    Analyzes the pcapng file to extract the total retransmission delay per source IP,
    distinguishing between spurious, fast, and timeout-based retransmissions.
    
    Delay is now stored in SECONDS.
    """
    cap = pyshark.FileCapture(file_path)
    ip_delays = defaultdict(lambda: {"spurious": 0.0, "fast": 0.0, "timeout": 0.0})
    first_tx = {}
    
    for packet in cap:
        try:
            if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
                src_ip = packet.ip.src
                seq_num = packet.tcp.seq
                timestamp = float(packet.sniff_time.timestamp())
                key = (src_ip, seq_num)
                
                if hasattr(packet.tcp, 'analysis_retransmission'):
                    # Determine the type of retransmission
                    if hasattr(packet.tcp, 'analysis_spurious_retransmission'):
                        retrans_type = "spurious"
                    elif hasattr(packet.tcp, 'analysis_fast_retransmission'):
                        retrans_type = "fast"
                    else:
                        retrans_type = "timeout"
                    
                    if key in first_tx:
                        # Calculate delay in SECONDS (not ms)
                        delay = (timestamp - first_tx[key])
                        ip_delays[src_ip][retrans_type] += delay
                else:
                    if key not in first_tx:
                        first_tx[key] = timestamp
        except AttributeError:
            continue
    
    cap.close()
    return ip_delays

def filter_significant_delays(ip_delays):
    """
    Filters IPs by applying a per-type threshold: an IP's delay for a given retransmission type
    must exceed 5% of the overall delay for that type to be considered significant.
    """
    overall = {"spurious": 0.0, "fast": 0.0, "timeout": 0.0}
    for delays in ip_delays.values():
        overall["spurious"] += delays["spurious"]
        overall["fast"] += delays["fast"]
        overall["timeout"] += delays["timeout"]
    
    thresholds = {k: 0.05 * overall[k] for k in overall}
    
    significant = {}
    for ip, delays in ip_delays.items():
        filtered = {
            k: (v if v > thresholds[k] else 0.0) 
            for k, v in delays.items()
        }
        if sum(filtered.values()) > 0:
            significant[ip] = filtered
    return significant

def create_bokeh_visualization(ip_delays, all_ip_delays):
    """
    Creates a Bokeh visualization with:
      - A stacked bar chart showing the breakdown of retransmission delays
        (spurious, fast, timeout) in SECONDS for significant IPs.
      - A data table for all IPs.
      - A single hover tooltip that displays the full breakdown.
    """
    # Name of the output file
    output_file("plot9.html")
    
    types = ["spurious", "fast", "timeout"]
    ips = list(ip_delays.keys())
    
    # Prepare the data for the stacked bar chart
    data = {"ips": ips}
    for t in types:
        data[t] = [ip_delays[ip][t] for ip in ips]
    
    # Compute total per IP
    total_delays = [sum(ip_delays[ip].values()) for ip in ips]
    data["total"] = total_delays
    
    source = ColumnDataSource(data=data)
    
    # Create the figure
    p = figure(
        x_range=ips,
        title="Significant Retransmission Delays by IP (in seconds)",
        x_axis_label="Source IP",
        y_axis_label="Delay (s)",
        height=400,
        width=800,
        tools="pan,wheel_zoom,box_zoom,reset"
    )
    
    # Stacked bar chart (no 'name' argument => single hover context)
    p.vbar_stack(
        stackers=types,
        x="ips",
        width=0.5,
        color=["#c9d9d3", "#718dbf", "#e84d60"],
        source=source,
        legend_label=types
    )
    
    # Single hover tooltip that shows the entire row
    # Use numeric format specifiers to control decimals, e.g. @spurious{0.000}
    hover_tool = HoverTool(
        tooltips=[
            ("IP", "@ips"),
            ("Fast (s)", "@fast{0.000}"),
            ("Spurious (s)", "@spurious{0.000}"),
            ("Timeout (s)", "@timeout{0.000}"),
            ("Total (s)", "@total{0.000}")
        ],
        mode='mouse'
    )
    p.add_tools(hover_tool)
    
    p.xaxis.major_label_orientation = 1.0
    p.legend.location = "top_right"
    p.legend.title = "Retransmission Type"
    
    # Create data table for ALL IPs (including non-significant)
    table_rows = []
    for ip, delays in all_ip_delays.items():
        row = {
            "Source IP": ip,
            "Spurious (s)": delays.get("spurious", 0.0),
            "Fast (s)": delays.get("fast", 0.0),
            "Timeout (s)": delays.get("timeout", 0.0),
            "Total (s)": sum(delays.values())
        }
        table_rows.append(row)
    
    df = pd.DataFrame(table_rows)
    table_source = ColumnDataSource(df)
    columns = [
        TableColumn(field="Source IP", title="Source IP"),
        TableColumn(field="Spurious (s)", title="Spurious (s)"),
        TableColumn(field="Fast (s)", title="Fast (s)"),
        TableColumn(field="Timeout (s)", title="Timeout (s)"),
        TableColumn(field="Total (s)", title="Total (s)")
    ]
    data_table = DataTable(source=table_source, columns=columns, width=800, height=280)
    
    show(column(p, data_table))

if __name__ == "__main__":
    pcapng_file = sys.argv[1]  # Update this path
    all_ip_delays = analyze_pcapng(pcapng_file)
    significant_delays = filter_significant_delays(all_ip_delays)
    create_bokeh_visualization(significant_delays, all_ip_delays)

import pyshark
from collections import defaultdict
import math

from bokeh.plotting import figure, show
from bokeh.io import output_file
from bokeh.layouts import column, row
from bokeh.models import (
    ColumnDataSource, DataTable, TableColumn, HoverTool, Div
)
from bokeh.transform import cumsum
from bokeh.palettes import Category10

# ------------------------------------------------------------------------
# 1. Packet Loss Analysis
# ------------------------------------------------------------------------

def analyze_pcapng(file_path: str):
    """
    Parses a pcapng file (TCP only) and returns:
      1) A dict with total lost-packet counts by category:
         {
           'retransmissions': X,
           'lost_segments': Y,
           'spurious_retransmissions': Z,
           'duplicate_acks': W
         }
      2) A dict mapping source IP -> { 'retransmissions': ..., ... }
         to track per-IP lost-packet counts.
      3) The total number of TCP packets processed.
    """
    loss_types = ["retransmissions", "lost_segments", "spurious_retransmissions", "duplicate_acks"]
    total_loss = {lt: 0 for lt in loss_types}
    ip_loss = defaultdict(lambda: {lt: 0 for lt in loss_types})
    total_packets = 0

    capture = pyshark.FileCapture(file_path, display_filter="tcp")
    for packet in capture:
        total_packets += 1
        try:
            tcp_layer = packet.tcp
            src_ip = packet.ip.src
        except AttributeError:
            # Skip packets without TCP or IP layer.
            continue

        if hasattr(tcp_layer, 'analysis_retransmission'):
            total_loss["retransmissions"] += 1
            ip_loss[src_ip]["retransmissions"] += 1

        if hasattr(tcp_layer, 'analysis_lost_segment'):
            total_loss["lost_segments"] += 1
            ip_loss[src_ip]["lost_segments"] += 1

        if hasattr(tcp_layer, 'analysis_spurious_retransmission'):
            total_loss["spurious_retransmissions"] += 1
            ip_loss[src_ip]["spurious_retransmissions"] += 1

        if hasattr(tcp_layer, 'analysis_duplicate_ack'):
            total_loss["duplicate_acks"] += 1
            ip_loss[src_ip]["duplicate_acks"] += 1

    capture.close()
    return total_loss, ip_loss, total_packets

# ------------------------------------------------------------------------
# 2. Visualization
# ------------------------------------------------------------------------

def create_layout(total_loss: dict, ip_loss: dict, total_packets: int):
    """
    Builds a Bokeh layout with:
      - Row 1: Pie chart (left) and table (right) showing total lost packets by category.
               Below them, a line displays the overall packet loss percentage.
      - Row 2: A stacked bar chart for source IPs above a 5% threshold.
    
    If no losses are detected, appropriate messages are displayed.
    """
    loss_types = ["retransmissions", "lost_segments", "spurious_retransmissions", "duplicate_acks"]
    loss_labels = ["Retransmissions", "Lost Segments", "Spurious Retransmissions", "Duplicate ACKs"]

    total_lost = sum(total_loss.values())

    # Row 1: Pie Chart + Table + Loss Percentage
    if total_lost == 0:
        row1 = row(Div(text="<h2>No losses found in this pcapng file.</h2>", width=800))
        loss_percentage_div = Div(text="", width=800)
    else:
        # Prepare pie chart data
        data = {
            "type": loss_labels,
            "count": [total_loss[lt] for lt in loss_types]
        }
        data["angle"] = [
            (c / total_lost) * 2 * math.pi if total_lost > 0 else 0
            for c in data["count"]
        ]
        data["color"] = ["#718dbf", "#e84d60", "#c9d9d3", "#ddb7b1"]
        pie_source = ColumnDataSource(data=data)

        pie_fig = figure(
            title="Total Lost Packets by Category",
            tools="hover",
            tooltips="@type: @count",
            x_range=(-0.5, 1.0),
            width=400,
            height=400
        )
        pie_fig.wedge(
            x=0, y=1, radius=0.4,
            start_angle=cumsum('angle', include_zero=True),
            end_angle=cumsum('angle'),
            line_color="black",
            fill_color='color',
            legend_field='type',
            source=pie_source
        )
        pie_fig.axis.visible = False
        pie_fig.grid.grid_line_color = None

        # Table of losses
        table_data = {
            "Packet Loss Type": loss_labels,
            "Packets Lost": [total_loss[lt] for lt in loss_types]
        }
        table_source = ColumnDataSource(table_data)
        columns = [
            TableColumn(field="Packet Loss Type", title="Packet Loss Type"),
            TableColumn(field="Packets Lost", title="Packets Lost")
        ]
        data_table = DataTable(source=table_source, columns=columns, width=400, height=400)

        row1 = row(pie_fig, data_table)

        # Loss percentage calculation
        loss_percentage = (total_lost / total_packets) * 100 if total_packets > 0 else 0
        loss_percentage_div = Div(text=f"<h3>Packet Loss %: {loss_percentage:.2f}% (Lost {total_lost} of {total_packets} packets)</h3>", width=800)

    # Row 2: Stacked Bar Chart for Source IPs above threshold
    threshold_value = 0.05 * total_lost
    ip_info = {}
    for ip, losses in ip_loss.items():
        ip_total = sum(losses.values())
        ip_info[ip] = {
            "retransmissions": losses["retransmissions"],
            "lost_segments": losses["lost_segments"],
            "spurious_retransmissions": losses["spurious_retransmissions"],
            "duplicate_acks": losses["duplicate_acks"],
            "total": ip_total
        }
    threshold_ips = {ip: info for ip, info in ip_info.items() if info["total"] >= threshold_value}

    if total_lost == 0 or len(threshold_ips) == 0:
        row2 = row(Div(text="<h3>No source IP meets the 5% loss threshold, or no loss at all.</h3>", width=800))
    else:
        sorted_ips = sorted(threshold_ips.keys())
        data_all = {"ip": sorted_ips}
        for lt in loss_types:
            data_all[lt] = [threshold_ips[ip][lt] for ip in sorted_ips]
        data_all["total"] = [threshold_ips[ip]["total"] for ip in sorted_ips]

        bar_source = ColumnDataSource(data=data_all)

        bar_fig = figure(
            x_range=sorted_ips,
            title="Source IPs Above 5% Threshold (Stacked by Loss Type)",
            x_axis_label="Source IP",
            y_axis_label="Lost Packets",
            width=800,
            height=400,
            tools="pan,wheel_zoom,box_zoom,reset"
        )
        palette = Category10[len(loss_types)] if len(loss_types) <= 10 else None
        bar_fig.vbar_stack(
            stackers=loss_types,
            x="ip",
            width=0.5,
            color=palette,
            source=bar_source,
            legend_label=loss_labels
        )
        hover = HoverTool(tooltips=[("IP", "@ip"), ("Total Lost", "@total")])
        bar_fig.add_tools(hover)
        bar_fig.xaxis.major_label_orientation = 1.0
        bar_fig.legend.location = "top_right"
        bar_fig.legend.title = "Loss Types"

        row2 = row(bar_fig)

    layout = column(row1, loss_percentage_div, row2)
    return layout

# ------------------------------------------------------------------------
# 3. Main Script
# ------------------------------------------------------------------------

if __name__ == "__main__":
    pcapng_file = "20_11_24_bro_laptop_60ms_2min.pcapng"  # Replace with your pcapng file path

    total_loss, ip_loss, total_packets = analyze_pcapng(pcapng_file)
    final_layout = create_layout(total_loss, ip_loss, total_packets)

    output_file("plot8.html")
    show(final_layout)

import pyshark
from collections import defaultdict
import numpy as np

from bokeh.io import output_file, show
from bokeh.layouts import column
from bokeh.models import ColumnDataSource, HoverTool, NumeralTickFormatter, Select, CustomJS
from bokeh.plotting import figure
from datetime import datetime

def process_pcap(pcap_file):
    """
    Processes the PCAP file to extract retransmission delays.
    Returns:
        scatter_data_dict (dict): Mapping of conversations to timestamp and delay data.
        conversations (list): Sorted list of conversation keys.
    """
    capture = pyshark.FileCapture(pcap_file, display_filter='tcp')
    original_timestamps = defaultdict(dict)
    retransmission_events = defaultdict(list)
    
    for packet in capture:
        try:
            src = packet.ip.src
            dst = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            conv_key = f'{src}:{src_port} → {dst}:{dst_port}'

            seq = packet.tcp.seq
            timestamp = float(packet.sniff_timestamp)
            
            if hasattr(packet.tcp, 'analysis_retransmission') or 'tcp.analysis.retransmission' in packet.tcp.field_names:
                if seq in original_timestamps[conv_key]:
                    delay_ms = (timestamp - original_timestamps[conv_key][seq]) * 1000
                    retransmission_events[conv_key].append((timestamp * 1000, delay_ms))
            else:
                if seq not in original_timestamps[conv_key]:
                    original_timestamps[conv_key][seq] = timestamp
        except Exception:
            continue
    
    scatter_data_dict = {}
    all_times, all_delays = [], []
    conversations = []
    
    for conv, events in retransmission_events.items():
        if not events:
            continue
        events_sorted = sorted(events, key=lambda x: x[0])
        times = [t for t, delay in events_sorted]
        delays = [delay for t, delay in events_sorted]
        scatter_data_dict[conv] = {"time": times, "delay": delays}
        all_times.extend(times)
        all_delays.extend(delays)
        conversations.append(conv)
    
    scatter_data_dict["All Conversations"] = {"time": all_times, "delay": all_delays}
    conversations.append("All Conversations")
    conversations.sort()
    
    return scatter_data_dict, conversations

def create_scatter_plot(source, title):
    """
    Creates a scatter plot for retransmission delays over time.
    Returns:
        p_scatter (Figure): Bokeh scatter plot figure.
    """
    p_scatter = figure(
        x_axis_type='datetime',
        height=400,
        width=800,
        title=title,
        toolbar_location="above",
        tools="pan,wheel_zoom,box_zoom,reset,save"
    )
    p_scatter.scatter(
        x='time', y='delay', source=source,
        size=7, color="navy", alpha=0.5
    )
    p_scatter.xaxis.axis_label = "Timestamp"
    p_scatter.yaxis.axis_label = "Delay (ms)"
    p_scatter.yaxis.formatter = NumeralTickFormatter(format="0.0")
    
    hover = HoverTool(tooltips=[("Time", "@time{%F %T}"), ("Delay (ms)", "@delay{0.00}")],
                      formatters={'@time': 'datetime'})
    p_scatter.add_tools(hover)
    
    return p_scatter

def main():
    """
    Main function to process PCAP, create scatter plot, and show the visualization.
    """
    pcap_file = 'f0.pcapng'
    scatter_data_dict, conversations = process_pcap(pcap_file)
    
    default_conv = conversations[0] if conversations else ""
    default_data = scatter_data_dict.get(default_conv, {"time": [], "delay": []})
    source = ColumnDataSource(data=dict(time=default_data["time"], delay=default_data["delay"]))
    
    p_scatter = create_scatter_plot(source, f"Retransmission Delays Over Time: {default_conv}")
    
    conversation_select = Select(title="Select Conversation:", value=default_conv, options=conversations)
    
    callback_code = """
    var conv = conversation_select.value;
    var data = all_data[conv];
    source.data['time'] = data.time;
    source.data['delay'] = data.delay;
    
    if (data.delay.length > 0) {
        var min_delay = Math.min.apply(null, data.delay);
        var max_delay = Math.max.apply(null, data.delay);
        var pad = (max_delay - min_delay) * 0.05;
        if (pad < 1) { pad = 1; }
        p_scatter.y_range.start = min_delay - pad;
        p_scatter.y_range.end = max_delay + pad;
    } else {
        p_scatter.y_range.start = 0;
        p_scatter.y_range.end = 1;
    }
    
    if (data.time.length > 0) {
        var min_time = Math.min.apply(null, data.time);
        var max_time = Math.max.apply(null, data.time);
        var pad_time = (max_time - min_time) * 0.05;
        if (pad_time < 1000) { pad_time = 1000; }
        p_scatter.x_range.start = min_time - pad_time;
        p_scatter.x_range.end = max_time + pad_time;
    }
    
    p_scatter.title.text = "Retransmission Delays Over Time: " + conv;
    source.change.emit();
    """
    
    callback = CustomJS(args=dict(
        conversation_select=conversation_select,
        source=source,
        p_scatter=p_scatter,
        all_data=scatter_data_dict
    ), code=callback_code)
    
    conversation_select.js_on_change("value", callback)
    output_file("retransmission_scatter_analysis.html")
    show(column(conversation_select, p_scatter))

if __name__ == "__main__":
    main()
